#define _GNU_SOURCE
#include "collector.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool dm_canonical_ip(const char *input, char output[DM_IP_SIZE])
{
	unsigned char address[16];
	int family = strchr(input, ':') ? AF_INET6 : AF_INET;
	return inet_pton(family, input, address) == 1 &&
		inet_ntop(family, address, output, DM_IP_SIZE) != NULL;
}

static bool token(char *out, size_t capacity, const char **position)
{
	const char *start = *position;
	size_t length;
	while (*start == ' ') start++;
	*position = start;
	while (**position && !isspace((unsigned char)**position)) (*position)++;
	length = (size_t)(*position - start);
	if (!length || length >= capacity) return false;
	memcpy(out, start, length);
	out[length] = 0;
	return true;
}

bool dm_parse_query(const char *line, const char *client, time_t now, struct dm_record *record)
{
	const char *prefix = strstr(line, "dnsmasq["), *query, *end, *position;
	char address[DM_IP_SIZE], canonical[DM_IP_SIZE], verb[8];
	size_t length;
	struct tm date;
	time_t stamp;
	if (!prefix || !(end = strstr(prefix, "]: "))) return false;
	position = end + 3;
	/* log-queries=extra prefixes an ID and source-address/port. The query
	 * destination after 'from' is authoritative, not that optional prefix. */
	query = strstr(position, "query[");
	if (!query || (query != position && query[-1] != ' ')) return false;
	if (query != position) {
		const char *p = position;
		if (!isdigit((unsigned char)*p)) return false;
		while (isdigit((unsigned char)*p)) p++;
		if (*p++ != ' ') return false;
		if (p != query) {
			while (*p && *p != ' ') p++;
			if (*p++ != ' ' || p != query) return false;
		}
	}
	end = strchr(query + 6, ']');
	if (!end || end[1] != ' ') return false;
	length = (size_t)(end - (query + 6));
	if (!length || length >= sizeof(record->record_type)) return false;
	for (size_t i = 0; i < length; i++)
		if (!isalnum((unsigned char)query[6 + i]) && query[6 + i] != '=' && query[6 + i] != '_') return false;
	memcpy(record->record_type, query + 6, length);
	record->record_type[length] = 0;
	position = end + 2;
	if (!token(record->domain, sizeof(record->domain), &position) ||
	    !token(verb, sizeof(verb), &position) || strcmp(verb, "from") ||
	    !token(address, sizeof(address), &position) ||
	    !dm_canonical_ip(address, canonical) || strcmp(canonical, client)) return false;
	while (*position == ' ' || *position == '\r') position++;
	if (*position && strcmp(position, "(DNSSEC signed)")) return false;
	strcpy(record->client_ip, canonical);
	record->timestamp = now;
	/* dnsmasq's file logger uses ctime()+4: 'Oct 10 05:00:00'. */
	if (localtime_r(&now, &date)) {
		date.tm_isdst = -1;
		end = strptime(line, "%b %e %H:%M:%S", &date);
		if (end && *end == ' ') {
			stamp = mktime(&date);
			if (stamp > now + 86400) { date.tm_year--; date.tm_isdst = -1; stamp = mktime(&date); }
			if (stamp != (time_t)-1) record->timestamp = stamp;
		}
	}
	record->id = 0;
	return true;
}

int dm_ring_init(struct dm_ring *ring, size_t capacity)
{
	memset(ring, 0, sizeof(*ring));
	if (!capacity || capacity > SIZE_MAX / sizeof(*ring->records)) return -1;
	ring->records = calloc(capacity, sizeof(*ring->records));
	if (!ring->records) return -1;
	ring->capacity = capacity;
	return 0;
}

void dm_ring_clear(struct dm_ring *ring)
{
	ring->head = ring->count = 0;
	ring->captured = 0;
}

void dm_ring_free(struct dm_ring *ring)
{
	free(ring->records);
	memset(ring, 0, sizeof(*ring));
}

const struct dm_record *dm_ring_at(const struct dm_ring *ring, size_t index)
{
	return index < ring->count ? &ring->records[(ring->head + index) % ring->capacity] : NULL;
}

bool dm_ring_push(struct dm_ring *ring, const struct dm_record *record)
{
	size_t index;
	if (ring->captured == DM_SAFE_ID) return false;
	index = (ring->head + ring->count) % ring->capacity;
	if (ring->count == ring->capacity) ring->head = (ring->head + 1) % ring->capacity;
	else ring->count++;
	ring->records[index] = *record;
	ring->records[index].id = ++ring->captured;
	return true;
}

struct dm_page dm_ring_page(const struct dm_ring *ring, bool epoch_matches, uint64_t cursor, size_t limit)
{
	struct dm_page page = {0};
	uint64_t oldest = ring->count ? dm_ring_at(ring, 0)->id : 0;
	uint64_t newest = ring->count ? dm_ring_at(ring, ring->count - 1)->id : 0;
	page.reset = !epoch_matches || (cursor && (cursor > newest || (oldest && cursor < oldest - 1)));
	if (page.reset) cursor = 0;
	page.first = cursor && oldest ? (size_t)(cursor - oldest + 1) : 0;
	if (page.first > ring->count) page.first = ring->count;
	page.count = ring->count - page.first;
	if (page.count > limit) page.count = limit;
	page.cursor = page.count ? dm_ring_at(ring, page.first + page.count - 1)->id : cursor;
	page.more = page.first + page.count < ring->count;
	return page;
}

void dm_stream_feed(struct dm_stream *stream, struct dm_ring *ring, const char *client, const char *data, size_t size, time_t now)
{
	struct dm_record record;
	for (size_t i = 0; i < size; i++) {
		if (data[i] == '\n') {
			if (!stream->dropping) {
				stream->line[stream->used] = 0;
				if (dm_parse_query(stream->line, client, now, &record)) dm_ring_push(ring, &record);
			}
			stream->used = 0;
			stream->dropping = false;
		} else if (!stream->dropping) {
			if (!data[i] || stream->used == sizeof(stream->line) - 1) stream->dropping = true;
			else stream->line[stream->used++] = data[i];
		}
	}
}

void dm_file_init(struct dm_file *file)
{
	memset(file, 0, sizeof(*file));
	file->fd = -1;
}

void dm_file_close(struct dm_file *file)
{
	if (file->fd >= 0) close(file->fd);
	dm_file_init(file);
}

static void rewind_stream(struct dm_file *file)
{
	file->offset = 0;
	file->anchor_len = 0;
	memset(&file->stream, 0, sizeof(file->stream));
}

static int read_available(struct dm_file *file, struct dm_ring *ring, const char *client, time_t now)
{
	char buffer[8192];
	size_t remaining = DM_READ_BUDGET;
	while (remaining) {
		ssize_t size = pread(file->fd, buffer, remaining < sizeof(buffer) ? remaining : sizeof(buffer), file->offset);
		if (size < 0) { if (errno == EINTR) continue; return -1; }
		if (!size) break;
		dm_stream_feed(&file->stream, ring, client, buffer, (size_t)size, now);
		file->offset += size;
		remaining -= (size_t)size;
	}
	return 0;
}

int dm_file_finish(struct dm_file *file, struct dm_ring *ring, const char *client, time_t now)
{
	struct stat statbuf;
	if (file->fd < 0) return 0;
	if (fstat(file->fd, &statbuf) < 0) return -1;
	if (statbuf.st_size < file->offset) rewind_stream(file);
	if (read_available(file, ring, client, now) < 0 || fstat(file->fd, &statbuf) < 0) return -1;
	if (statbuf.st_size > file->offset)
		file->discarded_bytes += (uint64_t)(statbuf.st_size - file->offset);
	return 0;
}

static int poll_owned_inode(struct dm_file *file, size_t threshold, struct dm_ring *ring, const char *client, time_t now)
{
	struct stat fdstat;
	char anchor[sizeof(file->anchor)];
	ssize_t size;
	if (fstat(file->fd, &fdstat) < 0) return -1;
	if (fdstat.st_size < file->offset) rewind_stream(file);
	else if (file->anchor_len) {
		size = pread(file->fd, anchor, file->anchor_len, file->offset - (off_t)file->anchor_len);
		if (size < 0) return -1;
		if ((size_t)size != file->anchor_len || memcmp(anchor, file->anchor, file->anchor_len)) rewind_stream(file);
	}
	if (read_available(file, ring, client, now) < 0) return -1;
	if (fstat(file->fd, &fdstat) < 0) return -1;
	if ((uintmax_t)fdstat.st_size >= threshold) {
		/* dnsmasq uses O_APPEND: truncating this inode requires no restart. */
		if (ftruncate(file->fd, 0) < 0) return -1;
		if (fdstat.st_size > file->offset)
			file->discarded_bytes += (uint64_t)(fdstat.st_size - file->offset);
		rewind_stream(file);
	} else {
		file->anchor_len = file->offset < (off_t)sizeof(file->anchor) ? (size_t)file->offset : sizeof(file->anchor);
		if (file->anchor_len) {
			size = pread(file->fd, file->anchor, file->anchor_len, file->offset - (off_t)file->anchor_len);
			if (size < 0) return -1;
			if ((size_t)size != file->anchor_len) rewind_stream(file);
		}
	}
	return 0;
}

int dm_file_poll(struct dm_file *file, const char *path, size_t threshold, struct dm_ring *ring, const char *client, time_t now)
{
	struct stat pathstat, fdstat;
	int fault = 0;
	if (lstat(path, &pathstat) < 0) fault = errno;
	else if (!S_ISREG(pathstat.st_mode)) fault = EINVAL;
	else if (file->fd >= 0 && (file->device != pathstat.st_dev || file->inode != pathstat.st_ino)) fault = ESTALE;
	if (fault) {
		/* Request fail-stop, but keep the held jail inode bounded even when
		 * restore fails. Never follow a replacement while dnsmasq writes old. */
		if (file->fd >= 0 && poll_owned_inode(file, threshold, ring, client, now) < 0) return -1;
		errno = fault;
		return -1;
	}
	if (file->fd < 0) {
		file->fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
		if (file->fd < 0) return -1;
		if (fstat(file->fd, &fdstat) < 0 || !S_ISREG(fdstat.st_mode)) { dm_file_close(file); errno = EINVAL; return -1; }
		if (fdstat.st_dev != pathstat.st_dev || fdstat.st_ino != pathstat.st_ino) { dm_file_close(file); errno = ESTALE; return -1; }
		file->device = fdstat.st_dev;
		file->inode = fdstat.st_ino;
	}
	return poll_owned_inode(file, threshold, ring, client, now);
}
