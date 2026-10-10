#define _GNU_SOURCE
#include "collector.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <json-c/printbuf.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

#ifndef DM_DIRECTORY
#define DM_DIRECTORY "/tmp/dns-monitor"
#endif
#ifndef DM_HELPER
#define DM_HELPER "/usr/libexec/dns-monitor-lifecycle"
#endif
#ifndef DM_LEASES
#define DM_LEASES "/tmp/dhcp.leases"
#endif
#ifndef DM_ARP
#define DM_ARP "/proc/net/arp"
#endif
#ifndef DM_UBUS_SOCKET
#define DM_UBUS_SOCKET NULL
#endif
#define DM_LOG DM_DIRECTORY "/queries.log"
#define DM_LOCK DM_DIRECTORY "/daemon.lock"
#define DM_FREE_RESERVE (4 * 1024 * 1024)
#define DM_DIAGNOSTIC DM_DIRECTORY "/lifecycle.error"
#define DM_HELPER_TIMEOUT 35000
#define DM_CLIENT_LIMIT 512

static struct dm_ring ring;
static struct dm_file logfile;
static struct ubus_context *bus;
static struct blob_buf reply;
static struct uloop_timeout poll_timer, expiry_timer, retry_timer, helper_timer, connect_timer;
static struct uloop_process helper_process;
static struct uloop_fd signal_fd;
static struct ubus_request_data pending_request;
static bool pending, active, stopping, recovered, connected;
static int signal_pipe[2], lock_fd = -1;
static size_t max_log_bytes = 5242880;
static unsigned int session_seconds = 3600;
static time_t expires;
static char client[DM_IP_SIZE], epoch[80], boot_id[48], error_message[160];
static uint64_t epoch_sequence, discarded_bytes;
enum operation { OP_NONE, OP_START, OP_STOP, OP_RECOVER };
static enum operation operation;
static bool helper_timed_out;
static unsigned int helper_timeout_stage;
static struct ubus_object monitor_object;

static void begin_stop(void);
static int launch_helper(enum operation next);
static void connect_bus(struct uloop_timeout *timeout);

static void new_epoch(void)
{
	snprintf(epoch, sizeof(epoch), "%s-%" PRIu64, boot_id, ++epoch_sequence);
}

static void bounds(uint64_t *oldest, uint64_t *newest)
{
	*oldest = ring.count ? dm_ring_at(&ring, 0)->id : 0;
	*newest = ring.count ? dm_ring_at(&ring, ring.count - 1)->id : 0;
}

static void add_status(const char *error)
{
	uint64_t oldest, newest;
	bounds(&oldest, &newest);
	blobmsg_add_u8(&reply, "active", active);
	blobmsg_add_string(&reply, "client", client);
	blobmsg_add_u64(&reply, "captured", ring.captured);
	blobmsg_add_u32(&reply, "retained", ring.count);
	blobmsg_add_u32(&reply, "max_records", ring.capacity);
	blobmsg_add_u32(&reply, "max_log_bytes", max_log_bytes);
	blobmsg_add_string(&reply, "epoch", epoch);
	blobmsg_add_u64(&reply, "oldest", oldest);
	blobmsg_add_u64(&reply, "newest", newest);
	blobmsg_add_u64(&reply, "expires", active ? expires : 0);
	blobmsg_add_u64(&reply, "discarded_bytes", discarded_bytes + logfile.discarded_bytes);
	if (error && *error) blobmsg_add_string(&reply, "error", error);
	else if (*error_message) blobmsg_add_string(&reply, "error", error_message);
}

static int send_status(struct ubus_request_data *request, const char *error)
{
	blob_buf_init(&reply, 0);
	add_status(error);
	return ubus_send_reply(bus, request, reply.head);
}

static void complete_pending(void)
{
	if (!pending) return;
	if (connected) {
		send_status(&pending_request, NULL);
		ubus_complete_deferred_request(bus, &pending_request, UBUS_STATUS_OK);
	}
	pending = false;
}

static bool enough_space(size_t needed)
{
	struct statvfs fs;
	if (statvfs(DM_DIRECTORY, &fs) < 0) return false;
	return (uint64_t)fs.f_bavail * fs.f_frsize >= needed;
}

static void poll_capture(struct uloop_timeout *timeout)
{
	bool low_space;
	(void)timeout;
	if (!active) return;
	low_space = !enough_space(DM_FREE_RESERVE);
	if (low_space) {
		snprintf(error_message, sizeof(error_message), "Capture stopping: less than 4 MiB free temporary storage");
		begin_stop();
	}
	/* Continue draining/truncating while a restore is pending or failing;
	 * under memory pressure truncate sooner rather than waiting for restart. */
	if (dm_file_poll(&logfile, DM_LOG, low_space ? 4096 : max_log_bytes, &ring, client, time(NULL)) < 0) {
		int saved = errno;
		if (saved == ENOENT && operation == OP_STOP) goto reschedule;
		if (saved == ESTALE)
			snprintf(error_message, sizeof(error_message), "Capture stopping: logfile inode replaced (dnsmasq jail may still write old inode)");
		else
			snprintf(error_message, sizeof(error_message), "Capture stopping: logfile unavailable: %s", strerror(saved));
		begin_stop();
	}
reschedule:
	if (active) uloop_timeout_set(&poll_timer, 100);
}

static void session_expired(struct uloop_timeout *timeout)
{
	(void)timeout;
	if (!active) return;
	snprintf(error_message, sizeof(error_message), "Session time limit reached");
	begin_stop();
}

static void retry_operation(struct uloop_timeout *timeout)
{
	(void)timeout;
	if (operation != OP_NONE) return;
	if (!recovered) {
		if (launch_helper(OP_RECOVER) < 0) uloop_timeout_set(&retry_timer, 5000);
	} else if (active) begin_stop();
}

static void helper_deadline(struct uloop_timeout *timeout)
{
	(void)timeout;
	helper_timed_out = true;
	if (!helper_timeout_stage++) {
		kill(-helper_process.pid, SIGTERM);
		uloop_timeout_set(&helper_timer, 2000);
	} else {
		kill(-helper_process.pid, SIGKILL);
		kill(helper_process.pid, SIGKILL);
	}
}

static bool read_helper_error(void)
{
    struct stat st;
    ssize_t size;
    int fd = open(DM_DIAGNOSTIC, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
        close(fd);
        return false;
    }
    size = read(fd, error_message, sizeof(error_message) - 1);
    close(fd);
    if (size <= 0) return false;
    error_message[size] = 0;
    return true;
}

static void helper_finished(struct uloop_process *process, int status)
{
	enum operation finished = operation;
	bool success = !helper_timed_out && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	if (helper_timed_out) kill(-process->pid, SIGKILL);
	uloop_timeout_cancel(&helper_timer);
	operation = OP_NONE;
	if (!success) {
		if (helper_timed_out || !read_helper_error())
			snprintf(error_message, sizeof(error_message), "Lifecycle %s %s (status %d); logging state not confirmed off",
				finished == OP_START ? "start" : finished == OP_STOP ? "stop" : "recover",
				helper_timed_out ? "timed out" : "failed", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		if (finished == OP_START) {
			/* Even failed enable may have changed dnsmasq. Keep conservative
			 * active=true until the compensating stop is confirmed. */
			complete_pending();
			uloop_timeout_set(&poll_timer, 1);
			begin_stop();
		} else {
			if (finished == OP_RECOVER) {
				/* Withhold API until restoration succeeds, but still bound
				 * the leftover raw file during recovery faults. No client
				 * is selected, so no query records enter history. */
				active = true;
				uloop_timeout_set(&poll_timer, 1);
			}
			complete_pending();
			uloop_timeout_set(&retry_timer, 5000);
		}
		return;
	}
	if (finished == OP_RECOVER) {
		recovered = true;
		active = false;
		expires = 0;
		uloop_timeout_cancel(&poll_timer);
		uloop_timeout_cancel(&retry_timer);
		dm_file_close(&logfile);
		unlink(DM_LOG);
		error_message[0] = 0;
		if (stopping) { uloop_end(); return; }
		connect_bus(NULL);
	} else if (finished == OP_START) {
		error_message[0] = 0;
		expires = time(NULL) + session_seconds;
		uloop_timeout_set(&expiry_timer, session_seconds * 1000);
		poll_capture(NULL);
		complete_pending();
		if (stopping) begin_stop();
	} else {
		/* Only successful restore allows inactive state and raw-log removal. */
		dm_file_finish(&logfile, &ring, client, time(NULL));
		discarded_bytes += logfile.discarded_bytes;
		dm_file_close(&logfile);
		unlink(DM_LOG);
		active = false;
		expires = 0;
		uloop_timeout_cancel(&poll_timer);
		uloop_timeout_cancel(&expiry_timer);
		uloop_timeout_cancel(&retry_timer);
		/* Preserve automatic-stop reason; ordinary API stop clears it first. */
		complete_pending();
		if (stopping) uloop_end();
	}
}

static int launch_helper(enum operation next)
{
	pid_t pid;
	const char *command = next == OP_START ? "start" : next == OP_STOP ? "stop" : "recover";
	if (operation != OP_NONE) return -1;
	unlink(DM_DIAGNOSTIC);
	pid = fork();
	if (pid < 0) {
		snprintf(error_message, sizeof(error_message), "Cannot fork lifecycle helper: %s", strerror(errno));
		return -1;
	}
	if (!pid) {
		int nullfd;
		setpgid(0, 0);
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd >= 0) {
			dup2(nullfd, STDIN_FILENO);
			dup2(nullfd, STDOUT_FILENO);
			dup2(nullfd, STDERR_FILENO);
			if (nullfd > STDERR_FILENO) close(nullfd);
		}
		execl(DM_HELPER, DM_HELPER, command, (char *)NULL);
		_exit(127);
	}
	setpgid(pid, pid);
	operation = next;
	helper_timed_out = false;
	helper_timeout_stage = 0;
	helper_process.pid = pid;
	helper_process.cb = helper_finished;
	uloop_process_add(&helper_process);
	uloop_timeout_set(&helper_timer, DM_HELPER_TIMEOUT);
	return 0;
}

static void begin_stop(void)
{
	if (!recovered || !active || operation != OP_NONE || retry_timer.pending) return;
	if (launch_helper(OP_STOP) < 0) {
		complete_pending();
		uloop_timeout_set(&retry_timer, 5000);
	}
}

static const struct blobmsg_policy start_policy[] = {
	{ .name = "client", .type = BLOBMSG_TYPE_STRING }
};
static const struct blobmsg_policy queries_policy[] = {
	{ .name = "epoch", .type = BLOBMSG_TYPE_STRING },
	{ .name = "cursor", .type = BLOBMSG_TYPE_UNSPEC },
	{ .name = "limit", .type = BLOBMSG_TYPE_UNSPEC }
};
static const struct blobmsg_policy export_policy[] = {
	{ .name = "format", .type = BLOBMSG_TYPE_STRING },
	{ .name = "epoch", .type = BLOBMSG_TYPE_STRING },
	{ .name = "cursor", .type = BLOBMSG_TYPE_UNSPEC },
	{ .name = "limit", .type = BLOBMSG_TYPE_UNSPEC }
};

static void parse(const struct blobmsg_policy *policy, size_t count, struct blob_attr **attributes, struct blob_attr *message)
{
	memset(attributes, 0, count * sizeof(*attributes));
	if (message) blobmsg_parse(policy, count, attributes, blob_data(message), blob_len(message));
}

static bool integer(struct blob_attr *attribute, uint64_t *value)
{
	double number;
	if (!attribute) return false;
	switch (blobmsg_type(attribute)) {
	case BLOBMSG_TYPE_INT32:
		if ((int32_t)blobmsg_get_u32(attribute) < 0) return false;
		*value = blobmsg_get_u32(attribute);
		break;
	case BLOBMSG_TYPE_INT64: *value = blobmsg_get_u64(attribute); break;
	case BLOBMSG_TYPE_DOUBLE:
		number = blobmsg_get_double(attribute);
		if (!isfinite(number) || number < 0 || number > (double)DM_SAFE_ID || number != floor(number)) return false;
		*value = (uint64_t)number;
		break;
	default: return false;
	}
	return *value <= DM_SAFE_ID;
}

static int status_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	(void)context; (void)object; (void)method; (void)message;
	return send_status(request, NULL);
}

static int start_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	struct blob_attr *attributes[1];
	char selected[DM_IP_SIZE];
	(void)context; (void)object; (void)method;
	parse(start_policy, 1, attributes, message);
	if (!attributes[0] || !dm_canonical_ip(blobmsg_get_string(attributes[0]), selected))
		return send_status(request, "A valid IPv4 or IPv6 client address is required");
	if (operation != OP_NONE) return send_status(request, "Lifecycle operation in progress");
	if (active) return send_status(request, strcmp(selected, client) ? "Stop the active session before selecting another client" : NULL);
	if (stopping) return send_status(request, "Daemon is shutting down");
	if (!enough_space(max_log_bytes + DM_FREE_RESERVE)) return send_status(request, "Insufficient temporary storage for capture and 4 MiB reserve");
	dm_ring_clear(&ring);
	dm_file_close(&logfile);
	discarded_bytes = 0;
	new_epoch();
	strcpy(client, selected);
	error_message[0] = 0;
	active = true;
	expires = 0;
	ubus_defer_request(bus, request, &pending_request);
	pending = true;
	if (launch_helper(OP_START) < 0) {
		active = false; /* fork failed: helper never ran */
		complete_pending();
	}
	return UBUS_STATUS_OK;
}

static int stop_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	(void)context; (void)object; (void)method; (void)message;
	if (operation != OP_NONE) return send_status(request, "Lifecycle operation in progress");
	if (!active) return send_status(request, NULL);
	error_message[0] = 0;
	ubus_defer_request(bus, request, &pending_request);
	pending = true;
	begin_stop();
	return UBUS_STATUS_OK;
}

static int clear_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	(void)context; (void)object; (void)method; (void)message;
	if (operation != OP_NONE) return send_status(request, "Lifecycle operation in progress; retry clearing history");
	dm_ring_clear(&ring);
	new_epoch();
	/* Advance the raw reader first so clear cannot resurrect queued queries. */
	if (active && logfile.fd >= 0) {
		struct stat statbuf;
		if (!fstat(logfile.fd, &statbuf)) logfile.offset = statbuf.st_size;
		logfile.anchor_len = 0;
		memset(&logfile.stream, 0, sizeof(logfile.stream));
	}
	return send_status(request, NULL);
}

static void add_record(const struct dm_record *record)
{
	void *table = blobmsg_open_table(&reply, NULL);
	blobmsg_add_u64(&reply, "id", record->id);
	blobmsg_add_u64(&reply, "timestamp", record->timestamp);
	blobmsg_add_string(&reply, "client_ip", record->client_ip);
	blobmsg_add_string(&reply, "domain", record->domain);
	blobmsg_add_string(&reply, "record_type", record->record_type);
	blobmsg_close_table(&reply, table);
}

static int queries_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	struct blob_attr *attributes[3];
	struct dm_page page;
	uint64_t cursor = 0, limit = 500, oldest, newest;
	void *array, *table;
	bool matches;
	(void)context; (void)object; (void)method;
	parse(queries_policy, 3, attributes, message);
	if ((attributes[1] && !integer(attributes[1], &cursor)) ||
	    (attributes[2] && (!integer(attributes[2], &limit) || !limit))) return UBUS_STATUS_INVALID_ARGUMENT;
	if (limit > 500) limit = 500;
	matches = attributes[0] && !strcmp(blobmsg_get_string(attributes[0]), epoch);
	page = dm_ring_page(&ring, matches, cursor, limit);
	bounds(&oldest, &newest);
	blob_buf_init(&reply, 0);
	blobmsg_add_string(&reply, "epoch", epoch);
	blobmsg_add_u8(&reply, "reset", page.reset);
	blobmsg_add_u64(&reply, "oldest", oldest);
	blobmsg_add_u64(&reply, "newest", newest);
	blobmsg_add_u64(&reply, "cursor", page.cursor);
	blobmsg_add_u8(&reply, "more", page.more);
	array = blobmsg_open_array(&reply, "records");
	for (size_t i = 0; i < page.count; i++) add_record(dm_ring_at(&ring, page.first + i));
	blobmsg_close_array(&reply, array);
	table = blobmsg_open_table(&reply, "status");
	add_status(NULL);
	blobmsg_close_table(&reply, table);
	return ubus_send_reply(bus, request, reply.head);
}

static int csv_field(struct printbuf *output, const char *value)
{
	const char *start = value;
	if (printbuf_memappend(output, "\"", 1) < 0) return -1;
	for (; *value; value++) {
		if (*value != '"') continue;
		if (printbuf_memappend(output, start, value - start + 1) < 0 ||
		    printbuf_memappend(output, "\"", 1) < 0) return -1;
		start = value + 1;
	}
	if (printbuf_memappend(output, start, value - start) < 0) return -1;
	return printbuf_memappend(output, "\"", 1);
}

static int export_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	struct blob_attr *attributes[4];
	struct dm_page page;
	uint64_t cursor = 0, limit = 500, oldest, newest;
	void *table;
	const char *format;
	struct printbuf *output;
	char text[sizeof(struct dm_record) + 64];
	int length, result = UBUS_STATUS_UNKNOWN_ERROR;
	bool csv;
	(void)context; (void)object; (void)method;
	parse(export_policy, 4, attributes, message);
	if ((attributes[2] && !integer(attributes[2], &cursor)) ||
	    (attributes[3] && (!integer(attributes[3], &limit) || !limit))) return UBUS_STATUS_INVALID_ARGUMENT;
	if (limit > 500) limit = 500;
	page = dm_ring_page(&ring, attributes[1] && !strcmp(blobmsg_get_string(attributes[1]), epoch), cursor, limit);
	bounds(&oldest, &newest);
	format = attributes[0] ? blobmsg_get_string(attributes[0]) : "txt";
	if (strcmp(format, "txt") && strcmp(format, "csv")) return UBUS_STATUS_INVALID_ARGUMENT;
	csv = !strcmp(format, "csv");
	output = printbuf_new();
	if (!output) return UBUS_STATUS_UNKNOWN_ERROR;
	if (csv && (!cursor || page.reset) &&
	    printbuf_memappend(output, "timestamp,client_ip,domain,record_type\r\n",
		sizeof("timestamp,client_ip,domain,record_type\r\n") - 1) < 0) goto out;
	for (size_t i = 0; i < page.count; i++) {
		const struct dm_record *record = dm_ring_at(&ring, page.first + i);
		if (csv) {
			length = snprintf(text, sizeof(text), "%lld,", (long long)record->timestamp);
			if (printbuf_memappend(output, text, length) < 0 ||
			    csv_field(output, record->client_ip) < 0 || printbuf_memappend(output, ",", 1) < 0 ||
			    csv_field(output, record->domain) < 0 || printbuf_memappend(output, ",", 1) < 0 ||
			    csv_field(output, record->record_type) < 0 || printbuf_memappend(output, "\r\n", 2) < 0) goto out;
		} else {
			length = snprintf(text, sizeof(text), "%s\n", record->domain);
			if (length < 0 || (size_t)length >= sizeof(text) || printbuf_memappend(output, text, length) < 0) goto out;
		}
	}
	blob_buf_init(&reply, 0);
	blobmsg_add_string(&reply, "data", output->buf);
	blobmsg_add_string(&reply, "format", format);
	blobmsg_add_string(&reply, "epoch", epoch);
	blobmsg_add_u8(&reply, "reset", page.reset);
	blobmsg_add_u64(&reply, "oldest", oldest);
	blobmsg_add_u64(&reply, "newest", newest);
	blobmsg_add_u64(&reply, "cursor", page.cursor);
	blobmsg_add_u8(&reply, "more", page.more);
	table = blobmsg_open_table(&reply, "status");
	add_status(NULL);
	blobmsg_close_table(&reply, table);
	result = ubus_send_reply(bus, request, reply.head);
out:
	printbuf_free(output);
	return result;
}

struct client_entry { char ip[DM_IP_SIZE], hostname[256], mac[32]; bool lease, neighbour; };

static struct client_entry *find_client(struct client_entry *entries, size_t *count, const char *ip)
{
	char canonical[DM_IP_SIZE];
	if (!dm_canonical_ip(ip, canonical)) return NULL;
	for (size_t i = 0; i < *count; i++) if (!strcmp(entries[i].ip, canonical)) return &entries[i];
	if (*count == DM_CLIENT_LIMIT) return NULL;
	strcpy(entries[*count].ip, canonical);
	return &entries[(*count)++];
}

static bool mac_address(const char *value)
{
	if (strlen(value) != 17) return false;
	for (size_t i = 0; i < 17; i++)
		if (i % 3 == 2 ? value[i] != ':' : !isxdigit((unsigned char)value[i])) return false;
	return true;
}

static int clients_method(struct ubus_context *context, struct ubus_object *object, struct ubus_request_data *request, const char *method, struct blob_attr *message)
{
	struct client_entry *entries = calloc(DM_CLIENT_LIMIT, sizeof(*entries)), *entry;
	size_t count = 0, lines;
	FILE *stream;
	char line[1024], ip[DM_IP_SIZE], mac[32], hostname[256];
	unsigned long long lease_expires;
	unsigned int hardware, flags;
	void *array, *table;
	(void)context; (void)object; (void)method; (void)message;
	if (!entries) return UBUS_STATUS_UNKNOWN_ERROR;
	stream = fopen(DM_LEASES, "r");
	if (stream) {
		for (lines = 0; lines < 16384 && fgets(line, sizeof(line), stream); lines++) {
			if (!strchr(line, '\n') && !feof(stream)) { int ch; while ((ch = fgetc(stream)) != '\n' && ch != EOF) {} continue; }
			if (sscanf(line, "%llu %31s %45s %255s", &lease_expires, mac, ip, hostname) != 4 ||
			    (lease_expires && lease_expires < (unsigned long long)time(NULL))) continue;
			entry = find_client(entries, &count, ip);
			if (!entry) continue;
			entry->lease = true;
			if (strcmp(hostname, "*")) strcpy(entry->hostname, hostname);
			if (mac_address(mac)) strcpy(entry->mac, mac);
		}
		fclose(stream);
	}
	stream = fopen(DM_ARP, "r");
	if (stream) {
		for (lines = 0; lines < 16384 && fgets(line, sizeof(line), stream); lines++) {
			if (sscanf(line, "%45s %x %x %31s", ip, &hardware, &flags, mac) != 4 || !(flags & 2) || !mac_address(mac) || !strcmp(mac, "00:00:00:00:00:00")) continue;
			entry = find_client(entries, &count, ip);
			if (!entry) continue;
			entry->neighbour = true;
			strcpy(entry->mac, mac);
		}
		fclose(stream);
	}
	blob_buf_init(&reply, 0);
	array = blobmsg_open_array(&reply, "clients");
	for (size_t i = 0; i < count; i++) {
		table = blobmsg_open_table(&reply, NULL);
		blobmsg_add_string(&reply, "ip", entries[i].ip);
		blobmsg_add_string(&reply, "hostname", entries[i].hostname);
		blobmsg_add_string(&reply, "mac", entries[i].mac);
		blobmsg_add_string(&reply, "status", entries[i].lease ? entries[i].neighbour ? "lease+neighbour" : "lease" : "neighbour");
		blobmsg_close_table(&reply, table);
	}
	blobmsg_close_array(&reply, array);
	free(entries);
	return ubus_send_reply(bus, request, reply.head);
}

static const struct ubus_method monitor_methods[] = {
	UBUS_METHOD("start", start_method, start_policy),
	UBUS_METHOD_NOARG("stop", stop_method),
	UBUS_METHOD_NOARG("status", status_method),
	UBUS_METHOD("get_queries", queries_method, queries_policy),
	UBUS_METHOD_NOARG("clear", clear_method),
	UBUS_METHOD("export", export_method, export_policy),
	UBUS_METHOD_NOARG("get_clients", clients_method)
};
static struct ubus_object_type monitor_type = UBUS_OBJECT_TYPE("dns-monitor", monitor_methods);
static struct ubus_object monitor_object = {
	.name = "dns-monitor", .type = &monitor_type,
	.methods = monitor_methods, .n_methods = ARRAY_SIZE(monitor_methods)
};

static void connection_lost(struct ubus_context *context)
{
	(void)context;
	connected = false;
	pending = false;
	uloop_timeout_set(&connect_timer, 1000);
}

static void connect_bus(struct uloop_timeout *timeout)
{
	(void)timeout;
	if (!recovered || stopping) return;
	if (!bus) bus = ubus_connect(DM_UBUS_SOCKET);
	else if (ubus_reconnect(bus, DM_UBUS_SOCKET)) { uloop_timeout_set(&connect_timer, 1000); return; }
	if (!bus) { uloop_timeout_set(&connect_timer, 1000); return; }
	bus->connection_lost = connection_lost;
	ubus_add_uloop(bus);
	/* ubus_reconnect re-registers previously registered objects. */
	if (!monitor_object.id && ubus_add_object(bus, &monitor_object)) {
		uloop_timeout_set(&connect_timer, 1000);
		return;
	}
	connected = true;
}

static void terminate_signal(int signal_number)
{
	unsigned char byte = (unsigned char)signal_number;
	int saved = errno;
	if (write(signal_pipe[1], &byte, 1) < 0) { /* already signalled */ }
	errno = saved;
}

static void handle_signal(struct uloop_fd *fd, unsigned int events)
{
	unsigned char bytes[32];
	(void)events;
	while (read(fd->fd, bytes, sizeof(bytes)) > 0) {}
	stopping = true;
	uloop_timeout_cancel(&connect_timer);
	if (!recovered) {
		if (operation == OP_NONE && launch_helper(OP_RECOVER) < 0) uloop_timeout_set(&retry_timer, 5000);
	} else if (active) begin_stop();
	else uloop_end();
}

static bool numeric_option(const char *text, size_t minimum, size_t maximum, size_t *value)
{
	char *end;
	unsigned long long number;
	if (!*text || *text == '-') return false;
	errno = 0;
	number = strtoull(text, &end, 10);
	if (errno || *end || number < minimum || number > maximum) return false;
	*value = number;
	return true;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{"max-records", required_argument, NULL, 'r'},
		{"max-log-bytes", required_argument, NULL, 'b'},
		{"session-seconds", required_argument, NULL, 's'},
		{NULL, 0, NULL, 0}
	};
	size_t records = 10000, value;
	int option, randomfd;
	unsigned char random_bytes[16];
	struct stat directory;
	struct sigaction action = {0};
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		switch (option) {
		case 'r': if (!numeric_option(optarg, 1, 10000, &records)) goto usage; break;
		case 'b': if (!numeric_option(optarg, 4096, 67108864, &max_log_bytes)) goto usage; break;
		case 's': if (!numeric_option(optarg, 1, 86400, &value)) goto usage; session_seconds = value; break;
		default: goto usage;
		}
	}
	if (optind != argc) goto usage;
	umask(0077);
	if (mkdir(DM_DIRECTORY, 0711) < 0 && errno != EEXIST) { perror("dns-monitor directory"); return 1; }
	if (lstat(DM_DIRECTORY, &directory) < 0 || !S_ISDIR(directory.st_mode) || directory.st_uid != geteuid() || (directory.st_mode & 0022)) {
		fprintf(stderr, "dns-monitor: unsafe runtime directory\n"); return 1;
	}
	lock_fd = open(DM_LOCK, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) < 0) { fprintf(stderr, "dns-monitor: another instance owns capture or lock unavailable\n"); return 1; }
	if (dm_ring_init(&ring, records)) { fprintf(stderr, "dns-monitor: cannot allocate bounded history\n"); return 1; }
	dm_file_init(&logfile);
	randomfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (randomfd < 0 || read(randomfd, random_bytes, sizeof(random_bytes)) != sizeof(random_bytes)) { fprintf(stderr, "dns-monitor: cannot generate epoch\n"); return 1; }
	close(randomfd);
	for (size_t i = 0; i < sizeof(random_bytes); i++) snprintf(boot_id + i * 2, 3, "%02x", random_bytes[i]);
	new_epoch();
	if (uloop_init() || pipe2(signal_pipe, O_NONBLOCK | O_CLOEXEC)) { perror("dns-monitor event loop"); return 1; }
	poll_timer.cb = poll_capture;
	expiry_timer.cb = session_expired;
	retry_timer.cb = retry_operation;
	helper_timer.cb = helper_deadline;
	connect_timer.cb = connect_bus;
	signal_fd.fd = signal_pipe[0];
	signal_fd.cb = handle_signal;
	uloop_fd_add(&signal_fd, ULOOP_READ);
	action.sa_handler = terminate_signal;
	sigemptyset(&action.sa_mask);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	signal(SIGPIPE, SIG_IGN);
	/* A procd respawn must restore dnsmasq before publishing a fresh API. */
	if (launch_helper(OP_RECOVER) < 0) uloop_timeout_set(&retry_timer, 5000);
	uloop_run();
	if (bus) ubus_free(bus);
	blob_buf_free(&reply);
	dm_file_close(&logfile);
	dm_ring_free(&ring);
	close(signal_pipe[0]); close(signal_pipe[1]); close(lock_fd);
	uloop_done();
	return 0;
usage:
	fprintf(stderr, "Usage: dns-monitor [--max-records 1..10000] [--max-log-bytes 4096..67108864] [--session-seconds 1..86400]\n");
	return 2;
}
