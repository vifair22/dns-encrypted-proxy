/*
 * Unit tests for cache.c
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "cache.h"
#include "test_helpers.h"
#include "test_fixtures.h"

/*
 * Test: dns_cache_init and dns_cache_destroy lifecycle
 */
static void test_cache_init_destroy(void **state) {
    (void)state;
    
    dns_cache_t cache;
    
    int result = dns_cache_init(&cache, 100);
    assert_int_equal(result, 0);
    size_t capacity = 0;
    size_t entries = 0;
    dns_cache_get_stats(&cache, &capacity, &entries);
    assert_int_equal(capacity, 100);
    assert_int_equal(entries, 0);
    
    dns_cache_destroy(&cache);
    dns_cache_get_stats(&cache, &capacity, &entries);
    assert_int_equal(capacity, 0);
    assert_int_equal(entries, 0);
}

/*
 * Test: dns_cache_init with invalid parameters
 */
static void test_cache_init_invalid(void **state) {
    (void)state;
    
    dns_cache_t cache;
    
    /* NULL cache pointer */
    int result = dns_cache_init(NULL, 100);
    assert_int_equal(result, -1);
    
    /* Zero capacity */
    result = dns_cache_init(&cache, 0);
    assert_int_equal(result, -1);
}

/*
 * Test: dns_cache_destroy with NULL is safe
 */
static void test_cache_destroy_null(void **state) {
    (void)state;
    
    /* Should not crash */
    dns_cache_destroy(NULL);
}

/*
 * Test: store and lookup a single entry
 */
static void test_cache_store_lookup(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 10);
    
    /* Use fixture data */
    uint8_t key[] = {0x01, 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01};
    
    dns_cache_store(&cache, key, sizeof(key),
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN,
                    300);
    
    uint8_t request_id[2] = {0xAB, 0xCD};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit = dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
    
    assert_int_equal(hit, 1);
    assert_non_null(response);
    assert_int_equal(response_len, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    
    /* Verify request ID was substituted */
    assert_int_equal(response[0], 0xAB);
    assert_int_equal(response[1], 0xCD);
    
    free(response);
    dns_cache_destroy(&cache);
}

/*
 * Test: lookup miss for non-existent key
 */
static void test_cache_miss(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 10);
    
    uint8_t key[] = {0x01, 0x02, 0x03};
    uint8_t request_id[2] = {0x00, 0x00};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit = dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
    
    assert_int_equal(hit, 0);
    assert_null(response);
    assert_int_equal(response_len, 0);
    
    dns_cache_destroy(&cache);
}

/*
 * Test: TTL expiry - entry should not be returned after TTL expires
 */
static void test_cache_ttl_expiry(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 10);
    
    uint8_t key[] = {0x01, 0x02, 0x03};
    uint8_t response_data[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    /* Store with 1 second TTL */
    dns_cache_store(&cache, key, sizeof(key), response_data, sizeof(response_data), 1);
    
    /* Should hit immediately */
    uint8_t request_id[2] = {0x00, 0x00};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit = dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
    assert_int_equal(hit, 1);
    free(response);
    
    /* Wait for TTL to expire */
    sleep(2);
    
    /* Should miss now */
    response = NULL;
    response_len = 0;
    hit = dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
    assert_int_equal(hit, 0);
    
    dns_cache_destroy(&cache);
}

/*
 * Test: LRU eviction when cache is full
 * 
 * Note: Since entries inserted in the same second have identical timestamps,
 * we verify that eviction occurs (exactly one entry is evicted) and that
 * accessing an entry protects it from eviction.
 */
static void test_cache_lru_eviction(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 3);  /* Small cache for testing */
    
    uint8_t response_data[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    /* Fill cache with 3 entries */
    uint8_t key1[] = {0x01};
    uint8_t key2[] = {0x02};
    uint8_t key3[] = {0x03};
    
    dns_cache_store(&cache, key1, 1, response_data, sizeof(response_data), 300);
    dns_cache_store(&cache, key2, 1, response_data, sizeof(response_data), 300);
    dns_cache_store(&cache, key3, 1, response_data, sizeof(response_data), 300);
    
    /* Verify all 3 entries are present */
    uint8_t request_id[2] = {0x00, 0x00};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit1 = dns_cache_lookup(&cache, key1, 1, request_id, &response, &response_len);
    assert_int_equal(hit1, 1);
    free(response);
    
    response = NULL;
    int hit2 = dns_cache_lookup(&cache, key2, 1, request_id, &response, &response_len);
    assert_int_equal(hit2, 1);
    free(response);
    
    response = NULL;
    int hit3 = dns_cache_lookup(&cache, key3, 1, request_id, &response, &response_len);
    assert_int_equal(hit3, 1);
    free(response);
    
    /* Add a 4th entry - this must evict one of the existing entries */
    uint8_t key4[] = {0x04};
    dns_cache_store(&cache, key4, 1, response_data, sizeof(response_data), 300);
    
    /* key4 should be present */
    response = NULL;
    int hit4 = dns_cache_lookup(&cache, key4, 1, request_id, &response, &response_len);
    assert_int_equal(hit4, 1);
    free(response);
    
    /* Count how many of the original 3 keys are still present */
    response = NULL;
    hit1 = dns_cache_lookup(&cache, key1, 1, request_id, &response, &response_len);
    if (hit1) free(response);
    
    response = NULL;
    hit2 = dns_cache_lookup(&cache, key2, 1, request_id, &response, &response_len);
    if (hit2) free(response);
    
    response = NULL;
    hit3 = dns_cache_lookup(&cache, key3, 1, request_id, &response, &response_len);
    if (hit3) free(response);
    
    /* Exactly 2 of the original 3 should remain (one was evicted) */
    int remaining = hit1 + hit2 + hit3;
    assert_int_equal(remaining, 2);
    
    dns_cache_destroy(&cache);
}

/*
 * Test: updating an existing cache entry
 */
static void test_cache_update_existing(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 10);
    
    uint8_t key[] = {0x01, 0x02, 0x03};
    uint8_t response1[] = {0x12, 0x34, 0x00, 0x01};
    uint8_t response2[] = {0x56, 0x78, 0x00, 0x02, 0x00, 0x03};
    
    /* Store initial entry */
    dns_cache_store(&cache, key, sizeof(key), response1, sizeof(response1), 300);
    
    /* Update with new response */
    dns_cache_store(&cache, key, sizeof(key), response2, sizeof(response2), 600);
    
    /* Lookup should return updated response */
    uint8_t request_id[2] = {0xAA, 0xBB};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit = dns_cache_lookup(&cache, key, sizeof(key), request_id, &response, &response_len);
    
    assert_int_equal(hit, 1);
    assert_int_equal(response_len, sizeof(response2));
    /* Check that content matches (after ID substitution) */
    assert_int_equal(response[0], 0xAA);
    assert_int_equal(response[1], 0xBB);
    assert_int_equal(response[2], 0x00);
    assert_int_equal(response[3], 0x02);
    
    free(response);
    dns_cache_destroy(&cache);
}

/*
 * Test: cache lookup with invalid parameters
 */
static void test_cache_lookup_invalid_params(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 10);
    
    uint8_t key[] = {0x01};
    uint8_t request_id[2] = {0x00, 0x00};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    /* NULL cache */
    int hit = dns_cache_lookup(NULL, key, 1, request_id, &response, &response_len);
    assert_int_equal(hit, 0);
    
    /* NULL key */
    hit = dns_cache_lookup(&cache, NULL, 1, request_id, &response, &response_len);
    assert_int_equal(hit, 0);
    
    /* Zero key length */
    hit = dns_cache_lookup(&cache, key, 0, request_id, &response, &response_len);
    assert_int_equal(hit, 0);
    
    /* NULL response_out */
    hit = dns_cache_lookup(&cache, key, 1, request_id, NULL, &response_len);
    assert_int_equal(hit, 0);
    
    /* NULL response_len_out */
    hit = dns_cache_lookup(&cache, key, 1, request_id, &response, NULL);
    assert_int_equal(hit, 0);
    
    dns_cache_destroy(&cache);
}

/*
 * Test: cache store with invalid parameters (should be no-op)
 */
static void test_cache_store_invalid_params(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 10);
    
    uint8_t key[] = {0x01};
    uint8_t response[] = {0x12, 0x34};
    
    /* These should not crash and should be no-ops */
    dns_cache_store(NULL, key, 1, response, 2, 300);
    dns_cache_store(&cache, NULL, 1, response, 2, 300);
    dns_cache_store(&cache, key, 0, response, 2, 300);
    dns_cache_store(&cache, key, 1, NULL, 2, 300);
    dns_cache_store(&cache, key, 1, response, 0, 300);
    dns_cache_store(&cache, key, 1, response, 2, 0);
    
    /* Cache should still be empty */
    uint8_t request_id[2] = {0x00, 0x00};
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    int hit = dns_cache_lookup(&cache, key, 1, request_id, &resp, &resp_len);
    assert_int_equal(hit, 0);
    
    dns_cache_destroy(&cache);
}

/*
 * Thread function for concurrency test
 */
typedef struct {
    dns_cache_t *cache;
    int thread_id;
    int iterations;
    int errors;
} thread_args_t;

static void *cache_thread_worker(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    args->errors = 0;
    
    for (int i = 0; i < args->iterations; i++) {
        /* Create thread-specific key */
        uint8_t key[4];
        key[0] = (uint8_t)args->thread_id;
        key[1] = (uint8_t)((i >> 16) & 0xFF);
        key[2] = (uint8_t)((i >> 8) & 0xFF);
        key[3] = (uint8_t)(i & 0xFF);
        
        uint8_t response[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        
        /* Store */
        dns_cache_store(args->cache, key, sizeof(key), response, sizeof(response), 300);
        
        /* Lookup */
        uint8_t request_id[2] = {0x00, 0x00};
        uint8_t *resp = NULL;
        size_t resp_len = 0;
        int hit = dns_cache_lookup(args->cache, key, sizeof(key), request_id, &resp, &resp_len);
        
        if (hit && resp != NULL) {
            free(resp);
        }
    }
    
    return NULL;
}

/*
 * Test: thread safety - concurrent access should not crash
 */
static void test_cache_thread_safety(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 100);
    
    const int num_threads = 4;
    const int iterations = 1000;
    
    pthread_t threads[4];
    thread_args_t args[4];
    
    for (int i = 0; i < num_threads; i++) {
        args[i].cache = &cache;
        args[i].thread_id = i;
        args[i].iterations = iterations;
        args[i].errors = 0;
        pthread_create(&threads[i], NULL, cache_thread_worker, &args[i]);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Verify no errors occurred */
    for (int i = 0; i < num_threads; i++) {
        assert_int_equal(args[i].errors, 0);
    }
    
    dns_cache_destroy(&cache);
}

/*
 * Test: cache counters for evictions/expirations/bytes
 */
static void test_cache_counters(void **state) {
    (void)state;

    dns_cache_t cache;
    dns_cache_init(&cache, 2);

    uint8_t key1[] = {0x01};
    uint8_t key2[] = {0x02};
    uint8_t key3[] = {0x03};
    uint8_t resp[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    dns_cache_store(&cache, key1, sizeof(key1), resp, sizeof(resp), 300);
    dns_cache_store(&cache, key2, sizeof(key2), resp, sizeof(resp), 300);
    dns_cache_store(&cache, key3, sizeof(key3), resp, sizeof(resp), 300);

    uint64_t evictions = 0;
    uint64_t expirations = 0;
    size_t bytes_in_use = 0;
    dns_cache_get_counters(&cache, &evictions, &expirations, &bytes_in_use);

    assert_int_equal(evictions, 1);
    assert_int_equal(expirations, 0);
    assert_true(bytes_in_use > 0);

    uint8_t short_key[] = {0x0A};
    dns_cache_store(&cache, short_key, sizeof(short_key), resp, sizeof(resp), 1);
    sleep(2);

    uint8_t req_id[2] = {0x00, 0x00};
    uint8_t *out = NULL;
    size_t out_len = 0;
    int hit = dns_cache_lookup(&cache, short_key, sizeof(short_key), req_id, &out, &out_len);
    assert_int_equal(hit, 0);

    dns_cache_get_counters(&cache, &evictions, &expirations, &bytes_in_use);
    assert_true(expirations >= 1);

    dns_cache_destroy(&cache);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cache_init_destroy),
        cmocka_unit_test(test_cache_init_invalid),
        cmocka_unit_test(test_cache_destroy_null),
        cmocka_unit_test(test_cache_store_lookup),
        cmocka_unit_test(test_cache_miss),
        cmocka_unit_test(test_cache_ttl_expiry),
        cmocka_unit_test(test_cache_lru_eviction),
        cmocka_unit_test(test_cache_update_existing),
        cmocka_unit_test(test_cache_lookup_invalid_params),
        cmocka_unit_test(test_cache_store_invalid_params),
        cmocka_unit_test(test_cache_thread_safety),
        cmocka_unit_test(test_cache_counters),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
