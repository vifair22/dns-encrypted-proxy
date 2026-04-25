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
#include "dns_message.h"

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

static void test_cache_new_helpers_and_single_thread_mode(void **state) {
    (void)state;
    reset_alloc_stubs();

    unsetenv("DOH_PROXY_CACHE_SINGLE_THREAD");
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 0);

    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "0", 1);
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 0);
    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "false", 1);
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 0);
    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "FALSE", 1);
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 0);
    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "1", 1);
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 1);

    assert_int_equal((int)fast_index(13, 8, 7), 5);
    assert_int_equal((int)fast_index(13, 10, 9), 3);

    cache_shard_t shard;
    memset(&shard, 0, sizeof(shard));
    assert_int_equal(pthread_mutex_init(&shard.mutex, NULL), 0);
    dns_cache_t fake;
    memset(&fake, 0, sizeof(fake));
    fake.single_thread_mode = 1;
    shard_lock(&fake, &shard);
    shard_unlock(&fake, &shard);
    fake.single_thread_mode = 0;
    shard_lock(&fake, &shard);
    shard_unlock(&fake, &shard);
    pthread_mutex_destroy(&shard.mutex);

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 64), 0);
    assert_int_equal(cache.single_thread_mode, 1);
    assert_int_equal(cache.shard_count, 1);
    dns_cache_destroy(&cache);

    unsetenv("DOH_PROXY_CACHE_SINGLE_THREAD");
}

static void test_cache_new_branch_paths(void **state) {
    (void)state;
    reset_alloc_stubs();

    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "1", 1);
    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 64), 0);

    const uint8_t key[] = {0x01};
    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), NULL, &out, &out_len), 0);

    size_t cap = 1;
    size_t entries = 1;
    dns_cache_get_stats(NULL, &cap, &entries);
    assert_int_equal(cap, 0);
    assert_int_equal(entries, 0);
    uint64_t ev = 1;
    uint64_t ex = 1;
    size_t bytes = 1;
    dns_cache_get_counters(NULL, &ev, &ex, &bytes);
    assert_int_equal(ev, 0);
    assert_int_equal(ex, 0);
    assert_int_equal(bytes, 0);

    cache_shard_t shard;
    assert_int_equal(shard_init(&shard, 4), 0);
    cache_entry_t *e = calloc(1, sizeof(*e));
    assert_non_null(e);
    e->key = (uint8_t *)strdup("x");
    e->key_len = 1;
    e->response = (uint8_t *)strdup("yy");
    e->response_len = 2;
    e->hash = hash_key(e->key, e->key_len);
    size_t b = fast_index(e->hash, shard.bucket_count, shard.bucket_mask);
    shard.buckets[b] = e;
    shard.lru_head = e;
    shard.lru_tail = e;
    shard.entry_count = 1;
    shard.bytes_in_use = 1;
    remove_bucket_entry(&shard, b, e, NULL);
    assert_int_equal(shard.bytes_in_use, 0);
    remove_bucket_entry(NULL, 0, NULL, NULL);
    evict_lru_tail(NULL);
    shard_destroy(&shard);

    uint8_t k1[2] = {0};
    uint8_t k2[2] = {0};
    int found = 0;
    cache_shard_t *s0 = &cache.shards[0];
    for (uint32_t i = 0; i < 65536 && !found; i++) {
        uint8_t a[2] = {(uint8_t)(i & 0xFFu), (uint8_t)((i >> 8) & 0xFFu)};
        uint64_t ha = hash_key(a, 2);
        size_t ia = fast_index(ha, s0->bucket_count, s0->bucket_mask);
        for (uint32_t j = i + 1; j < 65536; j++) {
            uint8_t c[2] = {(uint8_t)(j & 0xFFu), (uint8_t)((j >> 8) & 0xFFu)};
            uint64_t hb = hash_key(c, 2);
            size_t ib = fast_index(hb, s0->bucket_count, s0->bucket_mask);
            if (ia == ib && (a[0] != c[0] || a[1] != c[1])) {
                memcpy(k1, a, 2);
                memcpy(k2, c, 2);
                found = 1;
                break;
            }
        }
    }
    assert_int_equal(found, 1);

    const uint8_t r1[2] = {0xAA, 0xBB};
    const uint8_t r2[2] = {0xCC, 0xDD};
    const uint8_t req_id[2] = {0x11, 0x22};
    dns_cache_store(&cache, k1, 2, r1, sizeof(r1), 60);
    dns_cache_store(&cache, k2, 2, r2, sizeof(r2), 60);

    uint64_t h1 = hash_key(k1, 2);
    size_t bi = fast_index(h1, s0->bucket_count, s0->bucket_mask);
    assert_non_null(s0->buckets[bi]);
    assert_true(s0->buckets[bi]->hash != h1);

    reset_alloc_stubs();
    g_now_time = 10;
    g_malloc_fail_on_call = 1;
    dns_cache_store(&cache, k1, 2, r1, sizeof(r1), 60);

    reset_alloc_stubs();
    g_now_time = 10;
    assert_int_equal(dns_cache_lookup(&cache, k1, 2, req_id, &out, &out_len), 1);
    free(out);

    assert_non_null(s0->buckets[bi]);
    assert_true(s0->buckets[bi]->hash == h1);

    /* expired lookup removal path after move-to-front */
    reset_alloc_stubs();
    g_now_time = 0;
    const uint8_t rx[2] = {0x10, 0x20};
    dns_cache_store(&cache, k1, 2, rx, sizeof(rx), 1);
    g_now_time = 5;
    assert_int_equal(dns_cache_lookup(&cache, k1, 2, req_id, &out, &out_len), 0);

    /* force bytes_in_use underflow guard branch during update */
    g_now_time = 0;
    dns_cache_store(&cache, k1, 2, r1, sizeof(r1), 60);
    s0->bytes_in_use = 0;
    dns_cache_store(&cache, k1, 2, r2, sizeof(r2), 60);

    /* insert allocation-failure path (key/response alloc) */
    reset_alloc_stubs();
    g_malloc_fail_on_call = 1;
    const uint8_t k3[2] = {0xFE, 0xED};
    dns_cache_store(&cache, k3, 2, r1, sizeof(r1), 60);

    dns_cache_destroy(&cache);
    unsetenv("DOH_PROXY_CACHE_SINGLE_THREAD");
}

static void test_cache_expired_lookup_in_collision_bucket_keeps_chain_valid(void **state) {
    (void)state;
    reset_alloc_stubs();

    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "1", 1);

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 64), 0);

    cache_shard_t *shard = &cache.shards[0];
    uint8_t k1[2] = {0};
    uint8_t k2[2] = {0};
    int found = 0;
    for (uint32_t i = 0; i < 65536 && !found; i++) {
        uint8_t a[2] = {(uint8_t)(i & 0xFFu), (uint8_t)((i >> 8) & 0xFFu)};
        uint64_t ha = hash_key(a, 2);
        size_t ia = fast_index(ha, shard->bucket_count, shard->bucket_mask);
        for (uint32_t j = i + 1; j < 65536; j++) {
            uint8_t b[2] = {(uint8_t)(j & 0xFFu), (uint8_t)((j >> 8) & 0xFFu)};
            uint64_t hb = hash_key(b, 2);
            size_t ib = fast_index(hb, shard->bucket_count, shard->bucket_mask);
            if (ia == ib) {
                memcpy(k1, a, 2);
                memcpy(k2, b, 2);
                found = 1;
                break;
            }
        }
    }
    assert_int_equal(found, 1);

    const uint8_t resp1[4] = {0x12, 0x34, 0x81, 0x80};
    const uint8_t resp2[4] = {0xAB, 0xCD, 0x81, 0x80};
    const uint8_t req_id[2] = {0xAA, 0x55};

    g_now_time = 100;
    dns_cache_store(&cache, k1, 2, resp1, sizeof(resp1), 1);   /* expires at 101 */
    dns_cache_store(&cache, k2, 2, resp2, sizeof(resp2), 60);  /* live, same bucket */

    uint8_t *out = NULL;
    size_t out_len = 0;

    g_now_time = 105;
    assert_int_equal(dns_cache_lookup(&cache, k1, 2, req_id, &out, &out_len), 0);

    g_now_time = 106;
    assert_int_equal(dns_cache_lookup(&cache, k2, 2, req_id, &out, &out_len), 1);
    assert_non_null(out);
    free(out);

    uint64_t hk2 = hash_key(k2, 2);
    size_t bi = fast_index(hk2, shard->bucket_count, shard->bucket_mask);
    cache_entry_t *it = shard->buckets[bi];
    int steps = 0;
    while (it != NULL && steps < 8) {
        steps++;
        it = it->bucket_next;
    }
    assert_true(steps < 8);

    dns_cache_destroy(&cache);
    unsetenv("DOH_PROXY_CACHE_SINGLE_THREAD");
}

static void test_cache_cycle_guard_prevents_lookup_and_store_lockup(void **state) {
    (void)state;
    reset_alloc_stubs();

    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "1", 1);
    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 32), 0);

    cache_shard_t *shard = &cache.shards[0];
    const uint8_t key_a[] = {0x11};
    const uint8_t key_b[] = {0x22};
    const uint8_t resp[] = {0x12, 0x34, 0x81, 0x80};

    cache_entry_t *a = calloc(1, sizeof(*a));
    cache_entry_t *b = calloc(1, sizeof(*b));
    assert_non_null(a);
    assert_non_null(b);

    a->key = (uint8_t *)malloc(sizeof(key_a));
    b->key = (uint8_t *)malloc(sizeof(key_b));
    a->response = (uint8_t *)malloc(sizeof(resp));
    b->response = (uint8_t *)malloc(sizeof(resp));
    assert_non_null(a->key);
    assert_non_null(b->key);
    assert_non_null(a->response);
    assert_non_null(b->response);

    memcpy(a->key, key_a, sizeof(key_a));
    memcpy(b->key, key_b, sizeof(key_b));
    memcpy(a->response, resp, sizeof(resp));
    memcpy(b->response, resp, sizeof(resp));

    a->key_len = sizeof(key_a);
    b->key_len = sizeof(key_b);
    a->response_len = sizeof(resp);
    b->response_len = sizeof(resp);
    a->ttl_seconds = 60;
    b->ttl_seconds = 60;
    a->expires_at = 1000;
    b->expires_at = 1000;
    a->hash = 1;
    b->hash = 2;

    size_t bi = 0;
    shard->buckets[bi] = a;
    a->bucket_next = b;
    b->bucket_next = a; /* intentional corruption cycle */
    shard->entry_count = 2;

    uint8_t req_id[2] = {0xAA, 0x55};
    uint8_t *out = NULL;
    size_t out_len = 0;

    assert_int_equal(dns_cache_lookup(&cache, (const uint8_t *)"missing", 7, req_id, &out, &out_len), 0);
    dns_cache_store(&cache, (const uint8_t *)"new", 3, resp, sizeof(resp), 60);

    a->bucket_next = b;
    b->bucket_next = NULL;
    dns_cache_destroy(&cache);
    unsetenv("DOH_PROXY_CACHE_SINGLE_THREAD");
}

static void test_cache_additional_guard_and_branch_paths(void **state) {
    (void)state;
    reset_alloc_stubs();

    unsetenv("DOH_PROXY_CACHE_SINGLE_THREAD");
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 0);
    setenv("DOH_PROXY_CACHE_SINGLE_THREAD", "yes", 1);
    assert_int_equal(env_flag_enabled("DOH_PROXY_CACHE_SINGLE_THREAD"), 1);

    assert_int_equal(dns_cache_init(NULL, 1), -1);

    dns_cache_t cache;
    memset(&cache, 0, sizeof(cache));
    uint8_t *out = NULL;
    size_t out_len = 0;
    const uint8_t key[] = {0xAA};
    const uint8_t resp[] = {0x11, 0x22};
    const uint8_t req_id[2] = {0x01, 0x02};

    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), req_id, &out, &out_len), 0);
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), NULL, &out, &out_len), 0);
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), req_id, NULL, &out_len), 0);
    assert_int_equal(dns_cache_lookup(&cache, key, sizeof(key), req_id, &out, NULL), 0);

    dns_cache_store(&cache, key, sizeof(key), resp, sizeof(resp), 0);
    dns_cache_store(&cache, key, sizeof(key), resp, 0, 10);

    cache_shard_t shard;
    memset(&shard, 0, sizeof(shard));
    shard_maybe_grow(&shard);
    shard_sweep_expired(NULL, 0, 1);
    shard_sweep_expired(&shard, 0, 0);

    shard.bucket_count = (size_t)-1;
    shard_maybe_grow(&shard);

    assert_int_equal(shard_init(&shard, 1), 0);
    assert_int_equal(key_equals(NULL, 1, key, sizeof(key)), 0);

    cache_entry_t *e1 = calloc(1, sizeof(*e1));
    cache_entry_t *e2 = calloc(1, sizeof(*e2));
    assert_non_null(e1);
    assert_non_null(e2);
    e1->key = (uint8_t *)strdup("k1");
    e2->key = (uint8_t *)strdup("k2");
    e1->response = (uint8_t *)strdup("r1");
    e2->response = (uint8_t *)strdup("r2");
    assert_non_null(e1->key);
    assert_non_null(e2->key);
    assert_non_null(e1->response);
    assert_non_null(e2->response);
    e1->key_len = 2;
    e2->key_len = 2;
    e1->response_len = 2;
    e2->response_len = 2;
    e1->hash = hash_key(e1->key, e1->key_len);
    e2->hash = e1->hash;

    size_t bi = fast_index(e1->hash, shard.bucket_count, shard.bucket_mask);
    e1->bucket_next = e2;
    shard.buckets[bi] = e1;
    shard.entry_count = 2;
    shard.bytes_in_use = entry_bytes(e1) + entry_bytes(e2);
    shard.lru_head = e1;
    shard.lru_tail = e2;
    e1->lru_prev = NULL;
    e1->lru_next = e2;
    e2->lru_prev = e1;
    e2->lru_next = NULL;

    remove_bucket_entry(&shard, bi, e2, e1);
    assert_int_equal(shard.entry_count, 1);

    evict_lru_tail(&shard);
    assert_true(shard.evictions >= 1);

    shard_destroy(&shard);
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
        cmocka_unit_test(test_cache_new_helpers_and_single_thread_mode),
        cmocka_unit_test(test_cache_new_branch_paths),
        cmocka_unit_test(test_cache_expired_lookup_in_collision_bucket_keeps_chain_valid),
        cmocka_unit_test(test_cache_cycle_guard_prevents_lookup_and_store_lockup),
        cmocka_unit_test(test_cache_additional_guard_and_branch_paths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
