#ifndef DNS_MONITOR_COLLECTOR_H
#define DNS_MONITOR_COLLECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define DM_IP_SIZE 46
#define DM_DOMAIN_SIZE 256
#define DM_TYPE_SIZE 32
#define DM_LINE_SIZE 2048
#define DM_READ_BUDGET (256 * 1024)
#define DM_SAFE_ID UINT64_C(9007199254740991)

struct dm_record {
	uint64_t id;
	time_t timestamp;
	char client_ip[DM_IP_SIZE];
	char domain[DM_DOMAIN_SIZE];
	char record_type[DM_TYPE_SIZE];
};

struct dm_ring {
	struct dm_record *records;
	size_t capacity, head, count;
	uint64_t captured;
};

struct dm_page {
	bool reset, more;
	size_t first, count;
	uint64_t cursor;
};

struct dm_stream {
	char line[DM_LINE_SIZE];
	size_t used;
	bool dropping;
};

struct dm_file {
	int fd;
	dev_t device;
	ino_t inode;
	off_t offset;
	uint64_t discarded_bytes;
	char anchor[64];
	size_t anchor_len;
	struct dm_stream stream;
};

bool dm_canonical_ip(const char *input, char output[DM_IP_SIZE]);
bool dm_parse_query(const char *line, const char *client, time_t now, struct dm_record *record);
int dm_ring_init(struct dm_ring *ring, size_t capacity);
void dm_ring_clear(struct dm_ring *ring);
void dm_ring_free(struct dm_ring *ring);
const struct dm_record *dm_ring_at(const struct dm_ring *ring, size_t index);
bool dm_ring_push(struct dm_ring *ring, const struct dm_record *record);
struct dm_page dm_ring_page(const struct dm_ring *ring, bool epoch_matches, uint64_t cursor, size_t limit);
void dm_stream_feed(struct dm_stream *stream, struct dm_ring *ring, const char *client, const char *data, size_t size, time_t now);
void dm_file_init(struct dm_file *file);
void dm_file_close(struct dm_file *file);
/* Threshold is a rotation trigger, not a write-time hard file-size bound.
 * At overload, bytes beyond the per-tick read budget are discarded on truncate. */
int dm_file_poll(struct dm_file *file, const char *path, size_t threshold, struct dm_ring *ring, const char *client, time_t now);
/* Final bounded drain after logging is disabled; works after helper unlinks.
 * The caller must close immediately afterwards (the anchor is not refreshed). */
int dm_file_finish(struct dm_file *file, struct dm_ring *ring, const char *client, time_t now);

#endif
