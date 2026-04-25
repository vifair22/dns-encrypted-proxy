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

#include "upstream.h"
#include "upstream_bootstrap.h"
#include "logger.h"

static int g_resolve_calls[UPSTREAM_MAX_SERVERS];
static int g_resolve_result[UPSTREAM_MAX_SERVERS];
static int g_resolve_sleep_ms = 0;

int upstream_resolve_on_server_with_deadline(
    upstream_client_t *client,
    int server_index,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)client;
    (void)query;
    (void)query_len;
    (void)deadline_ms;
    if (g_resolve_sleep_ms > 0) {
        struct timespec ts;
        ts.tv_sec = g_resolve_sleep_ms / 1000;
        ts.tv_nsec = (long)(g_resolve_sleep_ms % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
    g_resolve_calls[server_index]++;
    if (g_resolve_result[server_index] != 0) {
        return -1;
    }
    *response_out = malloc(4);
    assert_non_null(*response_out);
    (*response_out)[0] = (uint8_t)server_index;
    (*response_out)[1] = 0xAA;
    (*response_out)[2] = 0xBB;
    (*response_out)[3] = 0xCC;
    *response_len_out = 4;
    return 0;
}

void logger_logf(const char *func, const char *level, const char *fmt, ...) {
    (void)func;
    (void)level;
    (void)fmt;
}

int upstream_bootstrap_try_stage3(upstream_server_t *server, int timeout_ms, const char **reason_out) {
    (void)server;
    (void)timeout_ms;
    if (reason_out != NULL) {
        *reason_out = "stage3_stub";
    }
    return -1;
}

int upstream_bootstrap_try_stage2(
    upstream_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const char **reason_out) {
    (void)client;
    (void)server;
    (void)timeout_ms;
    if (reason_out != NULL) {
        *reason_out = "stage2_stub";
    }
    return -1;
}

upstream_stage1_cache_result_t upstream_bootstrap_stage1_prepare(upstream_server_t *server) {
    (void)server;
    return UPSTREAM_STAGE1_CACHE_HIT;
}

int upstream_bootstrap_stage1_hydrate(upstream_client_t *client, upstream_server_t *server, int timeout_ms) {
    (void)client;
    (void)server;
    (void)timeout_ms;
    return 0;
}

void upstream_bootstrap_stage1_invalidate(upstream_server_t *server) {
    (void)server;
}

#include "../../src/upstream_dispatch.c"

static void reset_stubs(void) {
    memset(g_resolve_calls, 0, sizeof(g_resolve_calls));
    g_resolve_sleep_ms = 0;
    for (int i = 0; i < UPSTREAM_MAX_SERVERS; i++) {
        g_resolve_result[i] = -1;
    }
}

typedef struct {
    upstream_facilitator_t *fac;
    int rc;
} resolve_thread_arg_t;

static void *resolve_thread_main(void *arg) {
    resolve_thread_arg_t *a = (resolve_thread_arg_t *)arg;
    uint8_t q[] = {0x33, 0x44};
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    a->rc = upstream_facilitator_resolve(a->fac, q, sizeof(q), &resp, &resp_len);
    free(resp);
    return NULL;
}

static void init_test_client(upstream_client_t *client) {
    memset(client, 0, sizeof(*client));
    assert_int_equal(pthread_mutex_init(&client->stage1_cache_mutex, NULL), 0);
}

static void destroy_test_client(upstream_client_t *client) {
    pthread_mutex_destroy(&client->stage1_cache_mutex);
}

static void test_priority_fallback_to_second_provider(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    init_test_client(&client);
    client.server_count = 2;
    client.config.pool_size = 1;
    client.config.timeout_ms = 1000;
    client.servers[0].type = UPSTREAM_TYPE_DOH;
    client.servers[1].type = UPSTREAM_TYPE_DOH;
    g_resolve_result[0] = -1;
    g_resolve_result[1] = 0;

    upstream_facilitator_t fac;
    assert_int_equal(upstream_facilitator_init(&fac, &client), 0);

    uint8_t q[] = {0x01, 0x02};
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    assert_int_equal(upstream_facilitator_resolve(&fac, q, sizeof(q), &resp, &resp_len), 0);
    assert_non_null(resp);
    assert_int_equal(resp_len, 4);
    assert_int_equal(resp[0], 1);
    free(resp);

    assert_true(g_resolve_calls[0] >= 1);
    assert_true(g_resolve_calls[1] >= 1);

    upstream_facilitator_destroy(&fac);
    destroy_test_client(&client);
}

static void test_deadline_expired_fails_fast(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    init_test_client(&client);
    client.server_count = 1;
    client.config.pool_size = 1;
    client.config.timeout_ms = 1;
    client.servers[0].type = UPSTREAM_TYPE_DOH;
    g_resolve_result[0] = -1;

    upstream_facilitator_t fac;
    assert_int_equal(upstream_facilitator_init(&fac, &client), 0);

    uint8_t q[] = {0x01};
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    assert_int_equal(upstream_facilitator_resolve(&fac, q, sizeof(q), &resp, &resp_len), -1);
    assert_null(resp);
    assert_int_equal(resp_len, 0);

    upstream_facilitator_destroy(&fac);
    destroy_test_client(&client);
}

static void test_dispatch_stats_exposed(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    init_test_client(&client);
    client.server_count = 2;
    client.config.pool_size = 2;
    client.config.timeout_ms = 1000;
    client.servers[0].type = UPSTREAM_TYPE_DOH;
    client.servers[1].type = UPSTREAM_TYPE_DOH;
    g_resolve_result[0] = 0;
    g_resolve_result[1] = 0;

    upstream_facilitator_t fac;
    assert_int_equal(upstream_facilitator_init(&fac, &client), 0);

    upstream_facilitator_stats_t stats;
    assert_int_equal(upstream_facilitator_get_stats(&fac, &stats), 0);
    assert_int_equal(stats.member_count, 4);

    uint8_t q[] = {0x07, 0x08};
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    assert_int_equal(upstream_facilitator_resolve(&fac, q, sizeof(q), &resp, &resp_len), 0);
    free(resp);

    struct timespec ts = {.tv_sec = 0, .tv_nsec = 2 * 1000 * 1000};
    nanosleep(&ts, NULL);
    assert_int_equal(upstream_facilitator_get_stats(&fac, &stats), 0);
    assert_int_equal(stats.submit_queue_depth, 0);
    assert_int_equal(stats.work_queue_depth, 0);
    assert_int_equal(stats.completed_queue_depth, 0);

    upstream_facilitator_destroy(&fac);
    destroy_test_client(&client);
}

static void test_cooldown_skips_failed_provider_member(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    init_test_client(&client);
    client.server_count = 2;
    client.config.pool_size = 1;
    client.config.timeout_ms = 1000;
    client.servers[0].type = UPSTREAM_TYPE_DOH;
    client.servers[1].type = UPSTREAM_TYPE_DOH;

    g_resolve_result[0] = -1;
    g_resolve_result[1] = 0;

    upstream_facilitator_t fac;
    assert_int_equal(upstream_facilitator_init(&fac, &client), 0);

    uint8_t q[] = {0x11, 0x22};
    uint8_t *resp = NULL;
    size_t resp_len = 0;
    assert_int_equal(upstream_facilitator_resolve(&fac, q, sizeof(q), &resp, &resp_len), 0);
    free(resp);

    int provider0_calls_after_first = g_resolve_calls[0];

    resp = NULL;
    resp_len = 0;
    assert_int_equal(upstream_facilitator_resolve(&fac, q, sizeof(q), &resp, &resp_len), 0);
    free(resp);

    assert_int_equal(g_resolve_calls[0], provider0_calls_after_first);
    assert_true(g_resolve_calls[1] >= 2);

    upstream_facilitator_destroy(&fac);
    destroy_test_client(&client);
}

static void test_inflight_failure_drain_no_job_loss(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    init_test_client(&client);
    client.server_count = 1;
    client.config.pool_size = 1;
    client.config.timeout_ms = 1000;
    client.config.max_inflight_doh = 4;
    client.servers[0].type = UPSTREAM_TYPE_DOH;

    g_resolve_result[0] = -1;
    g_resolve_sleep_ms = 25;

    upstream_facilitator_t fac;
    assert_int_equal(upstream_facilitator_init(&fac, &client), 0);

    enum { THREADS = 4 };
    pthread_t threads[THREADS];
    resolve_thread_arg_t args[THREADS];
    memset(args, 0, sizeof(args));

    for (int i = 0; i < THREADS; i++) {
        args[i].fac = &fac;
        assert_int_equal(pthread_create(&threads[i], NULL, resolve_thread_main, &args[i]), 0);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < THREADS; i++) {
        assert_int_equal(args[i].rc, -1);
    }
    assert_true(g_resolve_calls[0] >= 1);
    assert_true(g_resolve_calls[0] < THREADS);

    upstream_facilitator_destroy(&fac);
    destroy_test_client(&client);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_priority_fallback_to_second_provider),
        cmocka_unit_test(test_deadline_expired_fails_fast),
        cmocka_unit_test(test_dispatch_stats_exposed),
        cmocka_unit_test(test_cooldown_skips_failed_provider_member),
        cmocka_unit_test(test_inflight_failure_drain_no_job_loss),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
