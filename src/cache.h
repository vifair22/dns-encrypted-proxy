#ifndef CACHE_H
#define CACHE_H

#include <stddef.h>
#include <stdint.h>

#include <pthread.h>

typedef struct {
    uint8_t *key;
    size_t key_len;
    uint8_t *response;
    size_t response_len;
    uint32_t ttl_seconds;
    uint64_t inserted_at;
    uint64_t last_access;
    int in_use;
} cache_entry_t;

typedef struct {
    cache_entry_t *entries;
    size_t capacity;
    pthread_mutex_t mutex;
} dns_cache_t;

int dns_cache_init(dns_cache_t *cache, size_t capacity);
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

#endif
