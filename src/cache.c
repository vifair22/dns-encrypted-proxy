#include "cache.h"

#include "dns_message.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CACHE_DEFAULT_SHARDS 32
#define CACHE_REHASH_LOAD_NUM 3
#define CACHE_REHASH_LOAD_DEN 4
#define CACHE_ADMISSION_MIN_CAPACITY 256
#define CACHE_SWEEP_INTERVAL_SEC 1
#define CACHE_SWEEP_BUCKET_BUDGET 8

static uint64_t now_seconds(void) {
    return (uint64_t)time(NULL);
}

static uint64_t hash_key(const uint8_t *key, size_t key_len) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < key_len; i++) {
        h ^= (uint64_t)key[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static size_t next_pow2(size_t n) {
    size_t v = 1;
    while (v < n && v < (SIZE_MAX / 2)) {
        v <<= 1;
    }
    return v;
}

static size_t entry_bytes(const cache_entry_t *entry) {
    if (entry == NULL) {
        return 0;
    }
    return entry->key_len + entry->response_len;
}

static void lru_remove(cache_shard_t *shard, cache_entry_t *entry) {
    if (shard == NULL || entry == NULL) {
        return;
    }

    if (entry->lru_prev != NULL) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        shard->lru_head = entry->lru_next;
    }

    if (entry->lru_next != NULL) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        shard->lru_tail = entry->lru_prev;
    }

    entry->lru_prev = NULL;
    entry->lru_next = NULL;
}

static void lru_push_front(cache_shard_t *shard, cache_entry_t *entry) {
    if (shard == NULL || entry == NULL) {
        return;
    }

    entry->lru_prev = NULL;
    entry->lru_next = shard->lru_head;
    if (shard->lru_head != NULL) {
        shard->lru_head->lru_prev = entry;
    } else {
        shard->lru_tail = entry;
    }
    shard->lru_head = entry;
}

static int key_equals(const cache_entry_t *entry, uint64_t hash, const uint8_t *key, size_t key_len) {
    if (entry == NULL || entry->hash != hash || entry->key_len != key_len) {
        return 0;
    }
    return memcmp(entry->key, key, key_len) == 0;
}

static void remove_bucket_entry(cache_shard_t *shard, size_t bucket_idx, cache_entry_t *entry, cache_entry_t *prev) {
    if (shard == NULL || entry == NULL || bucket_idx >= shard->bucket_count) {
        return;
    }

    if (prev != NULL) {
        prev->bucket_next = entry->bucket_next;
    } else {
        shard->buckets[bucket_idx] = entry->bucket_next;
    }

    lru_remove(shard, entry);

    if (shard->entry_count > 0) {
        shard->entry_count--;
    }
    if (shard->bytes_in_use >= entry_bytes(entry)) {
        shard->bytes_in_use -= entry_bytes(entry);
    } else {
        shard->bytes_in_use = 0;
    }

    free(entry->key);
    free(entry->response);
    free(entry);
}

static void evict_lru_tail(cache_shard_t *shard) {
    if (shard == NULL || shard->lru_tail == NULL) {
        return;
    }

    cache_entry_t *victim = shard->lru_tail;
    size_t bucket_idx = (size_t)(victim->hash % (uint64_t)shard->bucket_count);
    cache_entry_t *iter = shard->buckets[bucket_idx];
    cache_entry_t *prev = NULL;
    while (iter != NULL && iter != victim) {
        prev = iter;
        iter = iter->bucket_next;
    }
    if (iter != NULL) {
        remove_bucket_entry(shard, bucket_idx, iter, prev);
        shard->evictions++;
    }
}

static int doorkeeper_should_admit(cache_shard_t *shard, uint64_t hash) {
    if (shard == NULL || shard->admit_bits == NULL || shard->admit_bit_count == 0) {
        return 1;
    }

    size_t idx = (size_t)(hash & (uint64_t)(shard->admit_bit_count - 1));
    size_t byte_idx = idx >> 3;
    uint8_t mask = (uint8_t)(1u << (idx & 7u));
    int was_set = (shard->admit_bits[byte_idx] & mask) != 0;

    if (was_set) {
        shard->admit_bits[byte_idx] &= (uint8_t)~mask;
        return 1;
    }

    shard->admit_bits[byte_idx] |= mask;
    return 0;
}

static void shard_sweep_expired(cache_shard_t *shard, uint64_t now, size_t bucket_budget) {
    if (shard == NULL || shard->bucket_count == 0 || bucket_budget == 0) {
        return;
    }

    size_t cursor = shard->sweep_bucket_cursor % shard->bucket_count;
    size_t scanned = 0;

    while (scanned < bucket_budget) {
        cache_entry_t *entry = shard->buckets[cursor];
        cache_entry_t *prev = NULL;
        while (entry != NULL) {
            cache_entry_t *next = entry->bucket_next;
            if (entry->expires_at <= now) {
                remove_bucket_entry(shard, cursor, entry, prev);
                shard->expirations++;
            } else {
                prev = entry;
            }
            entry = next;
        }

        cursor++;
        if (cursor >= shard->bucket_count) {
            cursor = 0;
        }
        scanned++;
    }

    shard->sweep_bucket_cursor = cursor;
    shard->last_sweep_at = now;
}

static int shard_rehash(cache_shard_t *shard, size_t new_bucket_count) {
    if (shard == NULL || new_bucket_count == 0) {
        return -1;
    }

    cache_entry_t **new_buckets = calloc(new_bucket_count, sizeof(*new_buckets));
    if (new_buckets == NULL) {
        return -1;
    }

    for (size_t i = 0; i < shard->bucket_count; i++) {
        cache_entry_t *entry = shard->buckets[i];
        while (entry != NULL) {
            cache_entry_t *next = entry->bucket_next;
            size_t idx = (size_t)(entry->hash % (uint64_t)new_bucket_count);
            entry->bucket_next = new_buckets[idx];
            new_buckets[idx] = entry;
            entry = next;
        }
    }

    free(shard->buckets);
    shard->buckets = new_buckets;
    shard->bucket_count = new_bucket_count;
    return 0;
}

static void shard_maybe_grow(cache_shard_t *shard) {
    if (shard == NULL || shard->bucket_count == 0) {
        return;
    }

    if ((shard->entry_count + 1) * CACHE_REHASH_LOAD_DEN <= shard->bucket_count * CACHE_REHASH_LOAD_NUM) {
        return;
    }

    if (shard->bucket_count > (SIZE_MAX / 2)) {
        return;
    }

    size_t new_bucket_count = shard->bucket_count << 1;
    (void)shard_rehash(shard, new_bucket_count);
}

static int shard_init(cache_shard_t *shard, size_t max_entries) {
    if (shard == NULL || max_entries == 0) {
        return -1;
    }

    memset(shard, 0, sizeof(*shard));
    shard->max_entries = max_entries;

    size_t desired_buckets = max_entries * 2;
    if (desired_buckets < 16) {
        desired_buckets = 16;
    }
    shard->bucket_count = next_pow2(desired_buckets);
    if (shard->bucket_count == 0) {
        return -1;
    }

    shard->buckets = calloc(shard->bucket_count, sizeof(*shard->buckets));
    if (shard->buckets == NULL) {
        memset(shard, 0, sizeof(*shard));
        return -1;
    }

    shard->sweep_bucket_cursor = 0;
    shard->last_sweep_at = 0;

    if (max_entries >= CACHE_ADMISSION_MIN_CAPACITY) {
        size_t bit_count = next_pow2(max_entries * 2);
        if (bit_count < 256) {
            bit_count = 256;
        }
        size_t byte_count = (bit_count + 7) / 8;
        shard->admit_bits = calloc(byte_count, sizeof(*shard->admit_bits));
        if (shard->admit_bits == NULL) {
            free(shard->buckets);
            memset(shard, 0, sizeof(*shard));
            return -1;
        }
        shard->admit_bit_count = bit_count;
    }

    if (pthread_mutex_init(&shard->mutex, NULL) != 0) {
        free(shard->admit_bits);
        free(shard->buckets);
        memset(shard, 0, sizeof(*shard));
        return -1;
    }

    return 0;
}

static void shard_destroy(cache_shard_t *shard) {
    if (shard == NULL) {
        return;
    }

    if (shard->buckets != NULL) {
        for (size_t i = 0; i < shard->bucket_count; i++) {
            cache_entry_t *entry = shard->buckets[i];
            while (entry != NULL) {
                cache_entry_t *next = entry->bucket_next;
                free(entry->key);
                free(entry->response);
                free(entry);
                entry = next;
            }
        }
        free(shard->buckets);
    }

    free(shard->admit_bits);

    pthread_mutex_destroy(&shard->mutex);
    memset(shard, 0, sizeof(*shard));
}

int dns_cache_init(dns_cache_t *cache, size_t capacity) {
    if (cache == NULL || capacity == 0) {
        return -1;
    }

    memset(cache, 0, sizeof(*cache));

    size_t shard_count = CACHE_DEFAULT_SHARDS;
    if (capacity < shard_count) {
        shard_count = capacity;
    }
    if (shard_count == 0) {
        return -1;
    }

    cache->shards = calloc(shard_count, sizeof(*cache->shards));
    if (cache->shards == NULL) {
        return -1;
    }

    cache->shard_count = shard_count;
    cache->max_entries = capacity;

    size_t base = capacity / shard_count;
    size_t rem = capacity % shard_count;

    for (size_t i = 0; i < shard_count; i++) {
        size_t shard_capacity = base + (i < rem ? 1 : 0);
        if (shard_capacity == 0) {
            shard_capacity = 1;
        }
        if (shard_init(&cache->shards[i], shard_capacity) != 0) {
            for (size_t j = 0; j < i; j++) {
                shard_destroy(&cache->shards[j]);
            }
            free(cache->shards);
            memset(cache, 0, sizeof(*cache));
            return -1;
        }
    }

    return 0;
}

void dns_cache_destroy(dns_cache_t *cache) {
    if (cache == NULL) {
        return;
    }

    if (cache->shards != NULL) {
        for (size_t i = 0; i < cache->shard_count; i++) {
            shard_destroy(&cache->shards[i]);
        }
        free(cache->shards);
    }

    memset(cache, 0, sizeof(*cache));
}

int dns_cache_lookup(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t request_id[2],
    uint8_t **response_out,
    size_t *response_len_out) {
    if (cache == NULL || key == NULL || key_len == 0 || response_out == NULL || response_len_out == NULL ||
        cache->shards == NULL || cache->shard_count == 0) {
        return 0;
    }

    *response_out = NULL;
    *response_len_out = 0;

    uint64_t hash = hash_key(key, key_len);
    uint64_t now = now_seconds();

    size_t shard_idx = (size_t)(hash % (uint64_t)cache->shard_count);
    cache_shard_t *shard = &cache->shards[shard_idx];

    pthread_mutex_lock(&shard->mutex);

    if (now >= shard->last_sweep_at + CACHE_SWEEP_INTERVAL_SEC) {
        shard_sweep_expired(shard, now, CACHE_SWEEP_BUCKET_BUDGET);
    }

    size_t bucket_idx = (size_t)(hash % (uint64_t)shard->bucket_count);
    cache_entry_t *entry = shard->buckets[bucket_idx];
    cache_entry_t *prev = NULL;
    while (entry != NULL) {
        if (key_equals(entry, hash, key, key_len)) {
            break;
        }
        prev = entry;
        entry = entry->bucket_next;
    }

    if (entry == NULL) {
        pthread_mutex_unlock(&shard->mutex);
        return 0;
    }

    if (entry->expires_at <= now) {
        remove_bucket_entry(shard, bucket_idx, entry, prev);
        shard->expirations++;
        pthread_mutex_unlock(&shard->mutex);
        return 0;
    }

    uint8_t *copy = malloc(entry->response_len);
    if (copy == NULL) {
        pthread_mutex_unlock(&shard->mutex);
        return 0;
    }

    memcpy(copy, entry->response, entry->response_len);
    size_t response_len = entry->response_len;
    uint32_t age = 0;
    if (entry->expires_at > now) {
        uint64_t remaining = entry->expires_at - now;
        if (entry->ttl_seconds > (uint32_t)remaining) {
            age = entry->ttl_seconds - (uint32_t)remaining;
        }
    }

    entry->last_access = now;
    lru_remove(shard, entry);
    lru_push_front(shard, entry);

    pthread_mutex_unlock(&shard->mutex);

    copy[0] = request_id[0];
    copy[1] = request_id[1];
    dns_adjust_response_ttls(copy, response_len, age);

    *response_out = copy;
    *response_len_out = response_len;
    return 1;
}

void dns_cache_store(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *response,
    size_t response_len,
    uint32_t ttl_seconds) {
    if (cache == NULL || key == NULL || key_len == 0 || response == NULL || response_len == 0 || ttl_seconds == 0 ||
        cache->shards == NULL || cache->shard_count == 0) {
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

    uint64_t hash = hash_key(key, key_len);
    uint64_t now = now_seconds();
    uint64_t expires_at = now + (uint64_t)ttl_seconds;

    size_t shard_idx = (size_t)(hash % (uint64_t)cache->shard_count);
    cache_shard_t *shard = &cache->shards[shard_idx];

    pthread_mutex_lock(&shard->mutex);

    if (now >= shard->last_sweep_at + CACHE_SWEEP_INTERVAL_SEC) {
        shard_sweep_expired(shard, now, CACHE_SWEEP_BUCKET_BUDGET);
    }

    size_t bucket_idx = (size_t)(hash % (uint64_t)shard->bucket_count);
    cache_entry_t *entry = shard->buckets[bucket_idx];
    while (entry != NULL) {
        if (key_equals(entry, hash, key, key_len)) {
            break;
        }
        entry = entry->bucket_next;
    }

    if (entry != NULL) {
        size_t old_bytes = entry_bytes(entry);

        free(key_copy);
        free(entry->response);

        entry->response = response_copy;
        entry->response_len = response_len;
        entry->ttl_seconds = ttl_seconds;
        entry->expires_at = expires_at;
        entry->last_access = now;

        size_t new_bytes = entry_bytes(entry);
        if (shard->bytes_in_use >= old_bytes) {
            shard->bytes_in_use -= old_bytes;
        } else {
            shard->bytes_in_use = 0;
        }
        shard->bytes_in_use += new_bytes;

        lru_remove(shard, entry);
        lru_push_front(shard, entry);

        pthread_mutex_unlock(&shard->mutex);
        return;
    }

    if (shard->entry_count >= shard->max_entries) {
        if (!doorkeeper_should_admit(shard, hash)) {
            shard->admissions_dropped++;
            pthread_mutex_unlock(&shard->mutex);
            free(key_copy);
            free(response_copy);
            return;
        }
        evict_lru_tail(shard);
    }

    shard_maybe_grow(shard);

    cache_entry_t *new_entry = calloc(1, sizeof(*new_entry));
    if (new_entry == NULL) {
        pthread_mutex_unlock(&shard->mutex);
        free(key_copy);
        free(response_copy);
        return;
    }

    new_entry->key = key_copy;
    new_entry->key_len = key_len;
    new_entry->response = response_copy;
    new_entry->response_len = response_len;
    new_entry->ttl_seconds = ttl_seconds;
    new_entry->expires_at = expires_at;
    new_entry->last_access = now;
    new_entry->hash = hash;

    new_entry->bucket_next = shard->buckets[bucket_idx];
    shard->buckets[bucket_idx] = new_entry;

    lru_push_front(shard, new_entry);
    shard->entry_count++;
    shard->bytes_in_use += entry_bytes(new_entry);

    pthread_mutex_unlock(&shard->mutex);
}

void dns_cache_get_stats(dns_cache_t *cache, size_t *capacity_out, size_t *entries_out) {
    if (capacity_out != NULL) {
        *capacity_out = 0;
    }
    if (entries_out != NULL) {
        *entries_out = 0;
    }

    if (cache == NULL || cache->shards == NULL) {
        return;
    }

    size_t entries = 0;
    for (size_t i = 0; i < cache->shard_count; i++) {
        cache_shard_t *shard = &cache->shards[i];
        pthread_mutex_lock(&shard->mutex);
        entries += shard->entry_count;
        pthread_mutex_unlock(&shard->mutex);
    }

    if (capacity_out != NULL) {
        *capacity_out = cache->max_entries;
    }
    if (entries_out != NULL) {
        *entries_out = entries;
    }
}

void dns_cache_get_counters(dns_cache_t *cache, uint64_t *evictions_out, uint64_t *expirations_out, size_t *bytes_in_use_out) {
    if (evictions_out != NULL) {
        *evictions_out = 0;
    }
    if (expirations_out != NULL) {
        *expirations_out = 0;
    }
    if (bytes_in_use_out != NULL) {
        *bytes_in_use_out = 0;
    }

    if (cache == NULL || cache->shards == NULL) {
        return;
    }

    uint64_t evictions = 0;
    uint64_t expirations = 0;
    size_t bytes_in_use = 0;

    for (size_t i = 0; i < cache->shard_count; i++) {
        cache_shard_t *shard = &cache->shards[i];
        pthread_mutex_lock(&shard->mutex);
        evictions += shard->evictions;
        expirations += shard->expirations;
        bytes_in_use += shard->bytes_in_use;
        pthread_mutex_unlock(&shard->mutex);
    }

    if (evictions_out != NULL) {
        *evictions_out = evictions;
    }
    if (expirations_out != NULL) {
        *expirations_out = expirations;
    }
    if (bytes_in_use_out != NULL) {
        *bytes_in_use_out = bytes_in_use;
    }
}
