#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "cache.h"

static uint32_t cache_rng_state = 0x12345678u;
static uint32_t cache_next_rand(void) {
    cache_rng_state = cache_rng_state * 1664525u + 1013904223u;
    return cache_rng_state;
}

int dns_adjust_response_ttls(uint8_t *message, size_t message_len, uint32_t age_seconds) {
    (void)message;
    (void)message_len;
    (void)age_seconds;
    return 0;
}

static int g_malloc_fail_on_call = 0;
static int g_malloc_calls = 0;
static int g_calloc_fail_on_call = 0;
static int g_calloc_calls = 0;
static int g_mutex_init_fail = 0;
static time_t g_now_time = 0;

static void reset_alloc_stubs(void) {
    g_malloc_fail_on_call = 0;
    g_malloc_calls = 0;
    g_calloc_fail_on_call = 0;
    g_calloc_calls = 0;
    g_mutex_init_fail = 0;
    g_now_time = 0;
}

static void *cache_wrap_malloc(size_t size) {
    g_malloc_calls++;
    if (g_malloc_fail_on_call > 0 && g_malloc_calls == g_malloc_fail_on_call) {
        return NULL;
    }
    return malloc(size);
}

static void *cache_wrap_calloc(size_t nmemb, size_t size) {
    g_calloc_calls++;
    if (g_calloc_fail_on_call > 0 && g_calloc_calls == g_calloc_fail_on_call) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static int cache_wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    if (g_mutex_init_fail) {
        return -1;
    }
    return pthread_mutex_init(mutex, attr);
}

static time_t cache_wrap_time(time_t *out) {
    if (out != NULL) {
        *out = g_now_time;
    }
    return g_now_time;
}

#define malloc cache_wrap_malloc
#define calloc cache_wrap_calloc
#define pthread_mutex_init cache_wrap_pthread_mutex_init
#define time cache_wrap_time

#include "../../src/cache.c"

#undef time
#undef pthread_mutex_init
#undef calloc
#undef malloc

static void test_cache_static_guard_paths(void **state) {
    (void)state;
    reset_alloc_stubs();

    assert_int_equal(next_pow2(1), 1);
    assert_true(next_pow2(17) >= 17);
    assert_int_equal(entry_bytes(NULL), 0);

    lru_remove(NULL, NULL);
    lru_push_front(NULL, NULL);

    cache_entry_t e;
    memset(&e, 0, sizeof(e));
    assert_int_equal(key_equals(NULL, 0, NULL, 0), 0);
    assert_int_equal(key_equals(&e, 1, (const uint8_t *)"x", 1), 0);

    assert_int_equal(shard_rehash(NULL, 0), -1);
}

static void test_shard_doorkeeper_and_sweep(void **state) {
    (void)state;
    reset_alloc_stubs();

    cache_shard_t shard;
    assert_int_equal(shard_init(&shard, 300), 0);
    assert_non_null(shard.admit_bits);

    uint64_t h = 0x1234;
    assert_int_equal(doorkeeper_should_admit(&shard, h), 0);
    assert_int_equal(doorkeeper_should_admit(&shard, h), 1);

    cache_entry_t *entry = calloc(1, sizeof(*entry));
    assert_non_null(entry);
    entry->key = (uint8_t *)strdup("k");
    entry->key_len = 1;
    entry->response = (uint8_t *)strdup("r");
    entry->response_len = 1;
    entry->hash = hash_key(entry->key, entry->key_len);
    entry->expires_at = 1;

    size_t b = (size_t)(entry->hash % (uint64_t)shard.bucket_count);
    shard.buckets[b] = entry;
    shard.lru_head = entry;
    shard.lru_tail = entry;
    shard.entry_count = 1;
    shard.bytes_in_use = entry_bytes(entry);
    shard.sweep_bucket_cursor = b;

    shard_sweep_expired(&shard, 10, 8);
    assert_int_equal(shard.entry_count, 0);
    assert_true(shard.expirations >= 1);

    shard_destroy(&shard);
}

static void test_shard_rehash_and_growth(void **state) {
    (void)state;
    reset_alloc_stubs();

    cache_shard_t shard;
    assert_int_equal(shard_init(&shard, 64), 0);
    size_t old_bucket_count = shard.bucket_count;

    cache_entry_t *entry = calloc(1, sizeof(*entry));
    assert_non_null(entry);
    entry->key = (uint8_t *)strdup("abc");
    entry->key_len = 3;
    entry->response = (uint8_t *)strdup("resp");
    entry->response_len = 4;
    entry->hash = hash_key(entry->key, entry->key_len);
    size_t b = (size_t)(entry->hash % (uint64_t)shard.bucket_count);
    shard.buckets[b] = entry;
    shard.lru_head = entry;
    shard.lru_tail = entry;
    shard.entry_count = 1;
    shard.bytes_in_use = entry_bytes(entry);

    assert_int_equal(shard_rehash(&shard, old_bucket_count * 2), 0);
    assert_int_equal(shard.bucket_count, old_bucket_count * 2);

    shard.entry_count = shard.bucket_count;
    shard_maybe_grow(&shard);
    assert_true(shard.bucket_count >= old_bucket_count * 2);

    shard.entry_count = 1;
    evict_lru_tail(&shard);
    assert_int_equal(shard.entry_count, 0);
    assert_true(shard.evictions >= 1);

    shard_destroy(&shard);
}

static void test_cache_randomized_branch_exploration(void **state) {
    (void)state;
    reset_alloc_stubs();

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 512), 0);

    uint8_t req_id[2] = {0xAA, 0x55};
    for (int i = 0; i < 20000; i++) {
        uint8_t key[32];
        size_t key_len = (size_t)((cache_next_rand() % 31) + 1);
        for (size_t j = 0; j < key_len; j++) {
            key[j] = (uint8_t)(cache_next_rand() & 0xFFu);
        }

        uint8_t resp[64];
        size_t resp_len = (size_t)((cache_next_rand() % 63) + 1);
        for (size_t j = 0; j < resp_len; j++) {
            resp[j] = (uint8_t)(cache_next_rand() & 0xFFu);
        }
        if (resp_len >= 2) {
            resp[0] = 0x12;
            resp[1] = 0x34;
        }

        uint32_t r = cache_next_rand() % 100;
        if (r < 55) {
            uint32_t ttl = (cache_next_rand() % 5 == 0) ? 1u : (uint32_t)((cache_next_rand() % 300) + 1);
            dns_cache_store(&cache, key, key_len, resp, resp_len, ttl);
        } else if (r < 95) {
            uint8_t *out = NULL;
            size_t out_len = 0;
            (void)dns_cache_lookup(&cache, key, key_len, req_id, &out, &out_len);
            free(out);
        } else {
            /* invalid input branches */
            dns_cache_store(&cache, NULL, key_len, resp, resp_len, 10);
            dns_cache_store(&cache, key, 0, resp, resp_len, 10);
            uint8_t *out = NULL;
            size_t out_len = 0;
            (void)dns_cache_lookup(&cache, NULL, key_len, req_id, &out, &out_len);
            (void)dns_cache_lookup(&cache, key, 0, req_id, &out, &out_len);
        }
    }

    size_t cap = 0, entries = 0;
    dns_cache_get_stats(&cache, &cap, &entries);
    assert_true(cap >= 512);

    uint64_t evictions = 0, expirations = 0;
    size_t bytes = 0;
    dns_cache_get_counters(&cache, &evictions, &expirations, &bytes);
    (void)evictions;
    (void)expirations;
    (void)bytes;

    dns_cache_destroy(&cache);
}

static void test_cache_allocation_and_init_failure_paths(void **state) {
    (void)state;
    reset_alloc_stubs();

    cache_shard_t shard;

    g_calloc_fail_on_call = 1;
    assert_int_equal(shard_init(&shard, 10), -1);

    reset_alloc_stubs();
    g_calloc_fail_on_call = 2;
    assert_int_equal(shard_init(&shard, 300), -1);

    reset_alloc_stubs();
    g_mutex_init_fail = 1;
    assert_int_equal(shard_init(&shard, 10), -1);

    reset_alloc_stubs();
    dns_cache_t cache;
    g_calloc_fail_on_call = 2; /* first shard buckets alloc after cache->shards alloc */
    assert_int_equal(dns_cache_init(&cache, 64), -1);
}

static void test_cache_lookup_and_store_failure_paths(void **state) {
    (void)state;
    reset_alloc_stubs();

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 1), 0);

    const uint8_t key[] = {0x01, 0x02, 0x03};
    const uint8_t resp[] = {0x12, 0x34, 0x81, 0x80};
    uint8_t req_id[2] = {0xAA, 0x55};

    g_now_time = 100;
    dns_cache_store(&cache, key, sizeof(key), resp, sizeof(resp), 2);

    g_now_time = 103;
    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), req_id, &out, &out_len), 0);

    g_now_time = 200;
    dns_cache_store(&cache, key, sizeof(key), resp, sizeof(resp), 10);

    reset_alloc_stubs();
    g_now_time = 200;
    g_malloc_fail_on_call = 1;
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), req_id, &out, &out_len), 0);

    reset_alloc_stubs();
    g_now_time = 205;
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), req_id, &out, &out_len), 1);
    assert_non_null(out);
    free(out);

    reset_alloc_stubs();
    g_malloc_fail_on_call = 1; /* key_copy fails */
    dns_cache_store(&cache, key, sizeof(key), resp, sizeof(resp), 5);

    reset_alloc_stubs();
    g_malloc_fail_on_call = 2; /* response_copy fails */
    dns_cache_store(&cache, key, sizeof(key), resp, sizeof(resp), 5);

    reset_alloc_stubs();
    g_now_time = 230;
    g_calloc_fail_on_call = 1; /* new_entry allocation fails */
    const uint8_t key2[] = {0x09, 0x08, 0x07};
    dns_cache_store(&cache, key2, sizeof(key2), resp, sizeof(resp), 5);

    dns_cache_destroy(&cache);
}

static void test_cache_doorkeeper_drop_path(void **state) {
    (void)state;
    reset_alloc_stubs();

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 8192), 0);
    assert_int_equal(cache.shard_count, 32);

    uint8_t selected[257][2];
    size_t selected_count = 0;
    for (uint32_t v = 0; v < 65536 && selected_count < 257; v++) {
        uint8_t k[2];
        k[0] = (uint8_t)(v & 0xFFu);
        k[1] = (uint8_t)((v >> 8) & 0xFFu);
        uint64_t h = hash_key(k, sizeof(k));
        if ((size_t)(h % (uint64_t)cache.shard_count) == 0) {
            selected[selected_count][0] = k[0];
            selected[selected_count][1] = k[1];
            selected_count++;
        }
    }
    assert_int_equal(selected_count, 257);

    uint8_t resp[4] = {0x12, 0x34, 0x81, 0x80};
    for (size_t i = 0; i < 256; i++) {
        dns_cache_store(&cache, selected[i], 2, resp, sizeof(resp), 60);
    }

    cache_shard_t *shard0 = &cache.shards[0];
    assert_int_equal(shard0->max_entries, 256);
    assert_int_equal(shard0->entry_count, 256);
    uint64_t dropped_before = shard0->admissions_dropped;

    dns_cache_store(&cache, selected[256], 2, resp, sizeof(resp), 60);

    assert_true(shard0->admissions_dropped >= dropped_before + 1);
    assert_int_equal(shard0->entry_count, 256);

    dns_cache_destroy(&cache);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cache_static_guard_paths),
        cmocka_unit_test(test_shard_doorkeeper_and_sweep),
        cmocka_unit_test(test_shard_rehash_and_growth),
        cmocka_unit_test(test_cache_randomized_branch_exploration),
        cmocka_unit_test(test_cache_allocation_and_init_failure_paths),
        cmocka_unit_test(test_cache_lookup_and_store_failure_paths),
        cmocka_unit_test(test_cache_doorkeeper_drop_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
