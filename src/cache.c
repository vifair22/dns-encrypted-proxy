#include "cache.h"

#include "dns_message.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_seconds(void) {
    return (uint64_t)time(NULL);
}

static void clear_entry(cache_entry_t *entry) {
    if (entry == NULL) {
        return;
    }

    free(entry->key);
    free(entry->response);
    memset(entry, 0, sizeof(*entry));
}

int dns_cache_init(dns_cache_t *cache, size_t capacity) {
    if (cache == NULL || capacity == 0) {
        return -1;
    }

    cache->entries = calloc(capacity, sizeof(cache_entry_t));
    if (cache->entries == NULL) {
        return -1;
    }

    cache->capacity = capacity;
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        free(cache->entries);
        cache->entries = NULL;
        cache->capacity = 0;
        return -1;
    }

    return 0;
}

void dns_cache_destroy(dns_cache_t *cache) {
    if (cache == NULL) {
        return;
    }

    if (cache->entries != NULL) {
        for (size_t i = 0; i < cache->capacity; i++) {
            clear_entry(&cache->entries[i]);
        }
        free(cache->entries);
    }

    pthread_mutex_destroy(&cache->mutex);
    memset(cache, 0, sizeof(*cache));
}

static int key_equals(const cache_entry_t *entry, const uint8_t *key, size_t key_len) {
    if (!entry->in_use || entry->key_len != key_len) {
        return 0;
    }
    return memcmp(entry->key, key, key_len) == 0;
}

int dns_cache_lookup(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t request_id[2],
    uint8_t **response_out,
    size_t *response_len_out) {
    if (cache == NULL || key == NULL || key_len == 0 || response_out == NULL || response_len_out == NULL) {
        return 0;
    }

    *response_out = NULL;
    *response_len_out = 0;

    uint64_t now = now_seconds();

    pthread_mutex_lock(&cache->mutex);
    for (size_t i = 0; i < cache->capacity; i++) {
        cache_entry_t *entry = &cache->entries[i];
        if (!key_equals(entry, key, key_len)) {
            continue;
        }

        uint64_t age = now - entry->inserted_at;
        if (age >= entry->ttl_seconds) {
            clear_entry(entry);
            continue;
        }

        uint8_t *copy = malloc(entry->response_len);
        if (copy == NULL) {
            pthread_mutex_unlock(&cache->mutex);
            return 0;
        }

        size_t response_len = entry->response_len;
        memcpy(copy, entry->response, response_len);
        entry->last_access = now;
        pthread_mutex_unlock(&cache->mutex);

        copy[0] = request_id[0];
        copy[1] = request_id[1];
        dns_adjust_response_ttls(copy, response_len, (uint32_t)age);

        *response_out = copy;
        *response_len_out = response_len;
        return 1;
    }

    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

static size_t pick_replacement_slot(dns_cache_t *cache) {
    for (size_t i = 0; i < cache->capacity; i++) {
        if (!cache->entries[i].in_use) {
            return i;
        }
    }

    size_t oldest = 0;
    uint64_t oldest_access = cache->entries[0].last_access;
    for (size_t i = 1; i < cache->capacity; i++) {
        if (cache->entries[i].last_access < oldest_access) {
            oldest = i;
            oldest_access = cache->entries[i].last_access;
        }
    }
    return oldest;
}

void dns_cache_store(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *response,
    size_t response_len,
    uint32_t ttl_seconds) {
    if (cache == NULL || key == NULL || key_len == 0 || response == NULL || response_len == 0 || ttl_seconds == 0) {
        return;
    }

    uint8_t *key_copy = malloc(key_len);
    uint8_t *response_copy = malloc(response_len);
    if (key_copy == NULL || response_copy == NULL) {
        free(key_copy);
        free(response_copy);
        return;
    }

    memcpy(key_copy, key, key_len);
    memcpy(response_copy, response, response_len);

    uint64_t now = now_seconds();

    pthread_mutex_lock(&cache->mutex);

    for (size_t i = 0; i < cache->capacity; i++) {
        cache_entry_t *entry = &cache->entries[i];
        if (key_equals(entry, key, key_len)) {
            clear_entry(entry);

            entry->key = key_copy;
            entry->key_len = key_len;
            entry->response = response_copy;
            entry->response_len = response_len;
            entry->ttl_seconds = ttl_seconds;
            entry->inserted_at = now;
            entry->last_access = now;
            entry->in_use = 1;

            pthread_mutex_unlock(&cache->mutex);
            return;
        }
    }

    size_t slot = pick_replacement_slot(cache);
    clear_entry(&cache->entries[slot]);

    cache->entries[slot].key = key_copy;
    cache->entries[slot].key_len = key_len;
    cache->entries[slot].response = response_copy;
    cache->entries[slot].response_len = response_len;
    cache->entries[slot].ttl_seconds = ttl_seconds;
    cache->entries[slot].inserted_at = now;
    cache->entries[slot].last_access = now;
    cache->entries[slot].in_use = 1;

    pthread_mutex_unlock(&cache->mutex);
}
