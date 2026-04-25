#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <stdint.h>

#include <pthread.h>

#include "errors.h"

typedef struct cache_entry {
    uint8_t *key;
    size_t key_len;
    uint8_t *response;
    size_t response_len;
    uint32_t ttl_seconds;
    uint64_t expires_at;
    uint64_t last_access;
    uint64_t hash;
    struct cache_entry *bucket_next;
    struct cache_entry *lru_prev;
    struct cache_entry *lru_next;
} cache_entry_t;

typedef struct {
    cache_entry_t **buckets;
    size_t bucket_count;
    size_t bucket_mask;
    uint8_t *admit_bits;
    size_t admit_bit_count;
    size_t max_entries;
    size_t entry_count;
    size_t bytes_in_use;
    uint64_t evictions;
    uint64_t expirations;
    uint64_t admissions_dropped;
    size_t sweep_bucket_cursor;
    uint64_t last_sweep_at;
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    pthread_mutex_t mutex;
} cache_shard_t __attribute__((aligned(64)));

typedef struct {
    cache_shard_t *shards;
    size_t shard_count;
    size_t shard_mask;
    size_t max_entries;
    int single_thread_mode;
} dns_cache_t;

proxy_status_t dns_cache_init(dns_cache_t *cache, size_t capacity);
void dns_cache_destroy(dns_cache_t *cache);

int dns_cache_lookup(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t request_id[2],
    uint8_t **response_out,
    size_t *response_len_out);

void dns_cache_store(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *response,
    size_t response_len,
    uint32_t ttl_seconds);

void dns_cache_get_stats(dns_cache_t *cache, size_t *capacity_out, size_t *entries_out);
void dns_cache_get_counters(dns_cache_t *cache, uint64_t *evictions_out, uint64_t *expirations_out, size_t *bytes_in_use_out);

#endif
