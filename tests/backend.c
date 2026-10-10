#define _GNU_SOURCE
#include "../src/collector.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *query = "Oct 10 05:06:07 dnsmasq[123]: query[A] Example.COM from 192.168.1.2\n";
static const char *other = "Oct 10 05:06:07 dnsmasq[123]: query[A] other.test from 192.168.1.2\n";

static time_t test_now(void)
{
	struct tm date = { .tm_year = 126, .tm_mon = 9, .tm_mday = 10, .tm_hour = 5, .tm_min = 6, .tm_sec = 10 };
	return mktime(&date);
}

static void parser_tests(void)
{
	struct dm_record record;
	char ip[DM_IP_SIZE], large[4096];
	assert(dm_canonical_ip("2001:0DB8:0000::1", ip));
	assert(!strcmp(ip, "2001:db8::1"));
	assert(!dm_canonical_ip("192.168.1.2; reboot", ip));
	assert(!dm_canonical_ip("fe80::1%br-lan", ip));
	assert(dm_parse_query("Oct 10 05:06:07 dnsmasq[123]: query[A] Example.COM from 192.168.1.2", "192.168.1.2", test_now(), &record));
	assert(!strcmp(record.domain, "Example.COM") && !strcmp(record.record_type, "A"));
	assert(record.timestamp == test_now() - 3);
	assert(dm_parse_query("Oct 10 05:06:07 dnsmasq[123]: 25 2001:db8::1/53001 query[AAAA] ipv6.test from 2001:0db8:0:0:0:0:0:1", "2001:db8::1", test_now(), &record));
	assert(!strcmp(record.client_ip, "2001:db8::1"));
	assert(dm_parse_query("Oct 10 05:06:07 dnsmasq[123]: 25 query[type=65] . from 192.168.1.2", "192.168.1.2", test_now(), &record));
	assert(!strcmp(record.record_type, "type=65"));
	assert(dm_parse_query("dnsmasq[123]: query[DNSKEY] example.test from 192.168.1.2 (DNSSEC signed)", "192.168.1.2", test_now(), &record));
	assert(record.timestamp == test_now());
	assert(dm_parse_query("dnsmasq[123]: query[NSAP_PTR] legacy.test from 192.168.1.2", "192.168.1.2", test_now(), &record));
	assert(!strcmp(record.record_type, "NSAP_PTR"));
	assert(!dm_parse_query("dnsmasq[123]: reply query[A] foo from 192.168.1.2", "192.168.1.2", test_now(), &record));
	assert(!dm_parse_query("dnsmasq[123]: query[A] foo from 192.168.1.20", "192.168.1.2", test_now(), &record));
	assert(!dm_parse_query("dnsmasq[123]: query[A] foo to 192.168.1.2", "192.168.1.2", test_now(), &record));
	assert(!dm_parse_query("dnsmasq[123]: query[A] foo from 192.168.1.2 garbage", "192.168.1.2", test_now(), &record));
	memset(large, 'a', sizeof(large));
	memcpy(large, "dnsmasq[1]: query[A] ", 21);
	strcpy(large + 300, " from 192.168.1.2");
	assert(!dm_parse_query(large, "192.168.1.2", test_now(), &record));
	assert(dm_parse_query("Dec 31 23:59:59 dnsmasq[1]: query[A] year.test from 192.168.1.2", "192.168.1.2", test_now(), &record));
	struct tm date;
	localtime_r(&record.timestamp, &date);
	assert(date.tm_year == 125);
}

static void ring_tests(void)
{
	struct dm_ring ring;
	struct dm_record record = { .timestamp = 123 };
	struct dm_page page;
	assert(!dm_ring_init(&ring, 3));
	page = dm_ring_page(&ring, false, 99, 2);
	assert(page.reset && !page.count && !page.cursor && !page.more);
	for (int i = 0; i < 7; i++) assert(dm_ring_push(&ring, &record));
	assert(ring.captured == 7 && ring.count == 3);
	assert(dm_ring_at(&ring, 0)->id == 5 && dm_ring_at(&ring, 2)->id == 7 && !dm_ring_at(&ring, 3));
	page = dm_ring_page(&ring, true, 0, 2);
	assert(!page.reset && page.first == 0 && page.count == 2 && page.cursor == 6 && page.more);
	page = dm_ring_page(&ring, true, 6, 2);
	assert(!page.reset && page.first == 2 && page.count == 1 && page.cursor == 7 && !page.more);
	page = dm_ring_page(&ring, true, 7, 2);
	assert(!page.reset && !page.count && page.cursor == 7 && !page.more);
	page = dm_ring_page(&ring, true, 1, 2);
	assert(page.reset && page.first == 0 && page.cursor == 6);
	page = dm_ring_page(&ring, true, 4, 2);
	assert(!page.reset && page.first == 0 && page.cursor == 6);
	page = dm_ring_page(&ring, true, 9, 2);
	assert(page.reset && page.first == 0);
	page = dm_ring_page(&ring, false, 6, 2);
	assert(page.reset && page.first == 0);
	dm_ring_clear(&ring);
	assert(!ring.count && !ring.captured);
	ring.captured = DM_SAFE_ID - 1;
	assert(dm_ring_push(&ring, &record));
	assert(dm_ring_at(&ring, 0)->id == DM_SAFE_ID);
	assert(!dm_ring_push(&ring, &record));
	dm_ring_free(&ring);
}

static void stream_tests(void)
{
	struct dm_stream stream = {0};
	struct dm_ring ring;
	char oversized[DM_LINE_SIZE + 100];
	assert(!dm_ring_init(&ring, 4));
	for (size_t i = 0; i < strlen(query); i++) dm_stream_feed(&stream, &ring, "192.168.1.2", query + i, 1, test_now());
	assert(ring.captured == 1);
	memset(oversized, 'x', sizeof(oversized));
	dm_stream_feed(&stream, &ring, "192.168.1.2", oversized, sizeof(oversized), test_now());
	dm_stream_feed(&stream, &ring, "192.168.1.2", query, strlen(query), test_now());
	assert(ring.captured == 1 && !stream.dropping && !stream.used);
	dm_stream_feed(&stream, &ring, "192.168.1.2", query, strlen(query), test_now());
	assert(ring.captured == 2);
	dm_stream_feed(&stream, &ring, "192.168.1.2", "garbage\0", 8, test_now());
	dm_stream_feed(&stream, &ring, "192.168.1.2", query, strlen(query), test_now());
	assert(ring.captured == 2);
	dm_stream_feed(&stream, &ring, "192.168.1.2", query, strlen(query), test_now());
	assert(ring.captured == 3);
	dm_ring_free(&ring);
}

static void append(int fd, const char *data, size_t size)
{
	assert(write(fd, data, size) == (ssize_t)size);
}

static void file_tests(void)
{
	char path[] = "/tmp/dns-monitor-backend-XXXXXX", moved[128];
	int fd = mkstemp(path);
	struct dm_file file;
	struct dm_ring ring;
	struct stat before, after;
	assert(fd >= 0 && !fstat(fd, &before));
	assert(fcntl(fd, F_SETFL, O_APPEND) == 0);
	assert(!dm_ring_init(&ring, 8));
	dm_file_init(&file);
	append(fd, query, strlen(query) - 1);
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) && !ring.captured);
	append(fd, "\n", 1);
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) && ring.captured == 1);
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) && ring.captured == 1);
	/* External same-inode truncation resets partial records, not the ring. */
	assert(!ftruncate(fd, 0));
	append(fd, other, strlen(other));
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) && ring.captured == 2);
	/* Truncate and regrow beyond old offset between polls: anchor detects it. */
	assert(!ftruncate(fd, 0));
	append(fd, query, strlen(query)); append(fd, query, strlen(query));
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) && ring.captured == 4);
	for (int i = 0; i < 100; i++) append(fd, query, strlen(query));
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()));
	assert(!fstat(fd, &after) && after.st_ino == before.st_ino && after.st_size == 0);
	assert(file.offset == 0 && !file.stream.used);
	append(fd, other, strlen(other));
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) && !strcmp(dm_ring_at(&ring, ring.count - 1)->domain, "other.test"));
	/* Per-tick work stays bounded even when raw backlog exceeds threshold. */
	for (int i = 0; i < 6000; i++) append(fd, query, strlen(query));
	assert(!dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()));
	assert(file.discarded_bytes > 0 && !fstat(fd, &after) && !after.st_size);
	/* Replacement is fail-stop: don't follow an inode absent from the jail. */
	snprintf(moved, sizeof(moved), "%s.old", path);
	assert(!rename(path, moved));
	int replacement = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
	assert(replacement >= 0);
	append(replacement, query, strlen(query));
	assert(dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) == -1 && errno == ESTALE);
	/* A failed restore must still bound the original held logging inode. */
	for (int i = 0; i < 100; i++) append(fd, query, strlen(query));
	assert(dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) == -1 && errno == ESTALE);
	assert(!fstat(fd, &after) && !after.st_size);
	assert(!fstat(replacement, &after) && after.st_size == (off_t)strlen(query));
	/* Safe-stop helper may unlink first: the held inode still drains. */
	uint64_t captured = ring.captured;
	append(fd, query, strlen(query));
	assert(!unlink(moved));
	assert(!dm_file_finish(&file, &ring, "192.168.1.2", test_now()));
	assert(ring.captured == captured + 1);
	dm_file_close(&file);
	close(fd); close(replacement);
	assert(!unlink(path));
	assert(!symlink(moved, path));
	assert(dm_file_poll(&file, path, 4096, &ring, "192.168.1.2", test_now()) == -1 && errno == EINVAL);
	assert(!unlink(path));
	dm_file_close(&file);
	dm_ring_free(&ring);
}

int main(void)
{
	assert(!setenv("TZ", "UTC", 1));
	tzset();
	parser_tests(); ring_tests(); stream_tests(); file_tests();
	puts("backend: parser, ring, cursor, stream and file boundaries passed");
	return 0;
}
