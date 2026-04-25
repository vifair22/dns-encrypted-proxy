#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "upstream.h"
#include "upstream_bootstrap.h"
#include "upstream_doh.h"
#include "upstream_dot.h"
#include "upstream_doq.h"
#include "iterative_resolver.h"
#include "logger.h"

static int g_mutex_init_fail = 0;
static uint64_t g_now_ms = 0;

static int g_doh_init_rc = 0;
static int g_dot_init_rc = 0;
static int g_doq_init_rc = 0;
static int g_doh_resolve_rc = -1;
static int g_dot_resolve_rc = -1;
static int g_doq_resolve_rc = -1;
static int g_stage2_rc = -1;
static int g_stage3_rc = -1;
static const char *g_stage2_reason = "stub_stage2_failed";
static const char *g_stage3_reason = "stub_stage3_failed";
static int g_stage2_calls = 0;
static int g_stage3_calls = 0;
static int g_doh_failure_class = UPSTREAM_FAILURE_CLASS_UNKNOWN;
static uint64_t g_doh_transport_suppress_ms = 0;
static uint8_t g_resp_buf[16];
static size_t g_resp_len = 0;
static int g_doh_destroy_calls = 0;
static int g_dot_destroy_calls = 0;
static int g_doq_destroy_calls = 0;

#if UPSTREAM_DOH_ENABLED
#define PRIMARY_TEST_URL "https://dns.google/dns-query"
#define PRIMARY_TYPE UPSTREAM_TYPE_DOH
#elif UPSTREAM_DOT_ENABLED
#define PRIMARY_TEST_URL "tls://1.1.1.1:853"
#define PRIMARY_TYPE UPSTREAM_TYPE_DOT
#else
#define PRIMARY_TEST_URL "quic://9.9.9.9:853"
#define PRIMARY_TYPE UPSTREAM_TYPE_DOQ
#endif

static int resolve_any_server(
    upstream_client_t *client,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (client == NULL || query == NULL || query_len == 0 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }
    for (int i = 0; i < client->server_count; i++) {
        if (upstream_resolve_on_server(client, i, query, query_len, response_out, response_len_out) == 0) {
            return 0;
        }
    }
    return -1;
}

static void reset_stubs(void) {
    g_mutex_init_fail = 0;
    g_now_ms = 0;
    g_doh_init_rc = 0;
    g_dot_init_rc = 0;
    g_doq_init_rc = 0;
    g_doh_resolve_rc = -1;
    g_dot_resolve_rc = -1;
    g_doq_resolve_rc = -1;
    g_stage2_rc = -1;
    g_stage3_rc = -1;
    g_stage2_reason = "stub_stage2_failed";
    g_stage3_reason = "stub_stage3_failed";
    g_stage2_calls = 0;
    g_stage3_calls = 0;
    g_doh_failure_class = UPSTREAM_FAILURE_CLASS_UNKNOWN;
    g_doh_transport_suppress_ms = 0;
    g_resp_len = 0;
    g_doh_destroy_calls = 0;
    g_dot_destroy_calls = 0;
    g_doq_destroy_calls = 0;
}

static int upstream_wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    (void)mutex;
    (void)attr;
    if (g_mutex_init_fail) {
        return -1;
    }
    return 0;
}

static int upstream_wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

static int upstream_wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

static int upstream_wrap_pthread_mutex_destroy(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

static int upstream_wrap_clock_gettime(clockid_t clk, struct timespec *ts) {
    (void)clk;
    if (ts != NULL) {
        ts->tv_sec = (time_t)(g_now_ms / 1000);
        ts->tv_nsec = (long)((g_now_ms % 1000) * 1000000);
    }
    return 0;
}

int upstream_doh_client_init(upstream_doh_client_t **client, const upstream_config_t *config) {
    (void)config;
    if (g_doh_init_rc != 0) {
        return -1;
    }
    *client = (upstream_doh_client_t *)(uintptr_t)0x1111;
    return 0;
}

void upstream_doh_client_destroy(upstream_doh_client_t *client) {
    (void)client;
    g_doh_destroy_calls++;
}

int upstream_doh_resolve(
    upstream_doh_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)client;
    (void)timeout_ms;
    (void)query;
    (void)query_len;
    if (g_doh_resolve_rc != 0 || g_resp_len == 0) {
        server->stage.last_failure_class = g_doh_failure_class;
        if (g_doh_transport_suppress_ms > 0) {
            server->stage.transport_retry_suppress_until_ms = g_now_ms + g_doh_transport_suppress_ms;
        }
        return -1;
    }
    *response_out = malloc(g_resp_len);
    assert_non_null(*response_out);
    memcpy(*response_out, g_resp_buf, g_resp_len);
    *response_len_out = g_resp_len;
    return 0;
}

int upstream_doh_client_get_pool_stats(
    upstream_doh_client_t *client,
    int *capacity_out,
    int *in_use_out,
    uint64_t *http3_total_out,
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out) {
    (void)client;
    if (capacity_out) *capacity_out = 3;
    if (in_use_out) *in_use_out = 1;
    if (http3_total_out) *http3_total_out = 9;
    if (http2_total_out) *http2_total_out = 7;
    if (http1_total_out) *http1_total_out = 5;
    if (http_other_total_out) *http_other_total_out = 2;
    return 0;
}

int upstream_dot_client_init(upstream_dot_client_t **client, const upstream_config_t *config) {
    (void)config;
    if (g_dot_init_rc != 0) {
        return -1;
    }
    *client = (upstream_dot_client_t *)(uintptr_t)0x2222;
    return 0;
}

void upstream_dot_client_destroy(upstream_dot_client_t *client) {
    (void)client;
    g_dot_destroy_calls++;
}

int upstream_dot_resolve(
    upstream_dot_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)client;
    (void)server;
    (void)timeout_ms;
    (void)query;
    (void)query_len;
    if (g_dot_resolve_rc != 0 || g_resp_len == 0) {
        return -1;
    }
    *response_out = malloc(g_resp_len);
    assert_non_null(*response_out);
    memcpy(*response_out, g_resp_buf, g_resp_len);
    *response_len_out = g_resp_len;
    return 0;
}

int upstream_dot_client_get_pool_stats(
    upstream_dot_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out) {
    (void)client;
    if (capacity_out) *capacity_out = 4;
    if (in_use_out) *in_use_out = 2;
    if (alive_out) *alive_out = 1;
    return 0;
}

int upstream_doq_client_init(upstream_doq_client_t **client, const upstream_config_t *config) {
    (void)config;
    if (g_doq_init_rc != 0) {
        return -1;
    }
    *client = (upstream_doq_client_t *)(uintptr_t)0x3333;
    return 0;
}

void upstream_doq_client_destroy(upstream_doq_client_t *client) {
    (void)client;
    g_doq_destroy_calls++;
}

int upstream_doq_resolve(
    upstream_doq_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)client;
    (void)server;
    (void)timeout_ms;
    (void)query;
    (void)query_len;
    if (g_doq_resolve_rc != 0 || g_resp_len == 0) {
        return -1;
    }
    *response_out = malloc(g_resp_len);
    assert_non_null(*response_out);
    memcpy(*response_out, g_resp_buf, g_resp_len);
    *response_len_out = g_resp_len;
    return 0;
}

int upstream_doq_client_get_pool_stats(
    upstream_doq_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out) {
    (void)client;
    if (capacity_out) *capacity_out = 5;
    if (in_use_out) *in_use_out = 3;
    if (alive_out) *alive_out = 2;
    return 0;
}

proxy_status_t iterative_resolve_a(const char *hostname, int timeout_ms, uint32_t *addr_v4_be_out) {
    (void)hostname;
    (void)timeout_ms;
    (void)addr_v4_be_out;
    return PROXY_ERR_NETWORK;
}

int upstream_bootstrap_try_stage3(upstream_server_t *server, int timeout_ms, const char **reason_out) {
    (void)server;
    (void)timeout_ms;
    g_stage3_calls++;
    if (reason_out != NULL) {
        *reason_out = g_stage3_reason;
    }
    return g_stage3_rc;
}

int upstream_bootstrap_try_stage2(upstream_client_t *client, upstream_server_t *server, int timeout_ms, const char **reason_out) {
    (void)client;
    (void)server;
    (void)timeout_ms;
    g_stage2_calls++;
    if (reason_out != NULL) {
        *reason_out = g_stage2_reason;
    }
    return g_stage2_rc;
}

int upstream_bootstrap_stage1_hydrate(upstream_client_t *client, upstream_server_t *server, int timeout_ms) {
    (void)client;
    (void)server;
    (void)timeout_ms;
    return -1;
}

upstream_stage1_cache_result_t upstream_bootstrap_stage1_prepare(upstream_server_t *server) {
    (void)server;
    return UPSTREAM_STAGE1_CACHE_MISS;
}

void upstream_bootstrap_stage1_invalidate(upstream_server_t *server) {
    (void)server;
}

void logger_logf(const char *func, const char *level, const char *fmt, ...) {
    (void)func;
    (void)level;
    (void)fmt;
}

#define pthread_mutex_init upstream_wrap_pthread_mutex_init
#define pthread_mutex_lock upstream_wrap_pthread_mutex_lock
#define pthread_mutex_unlock upstream_wrap_pthread_mutex_unlock
#define pthread_mutex_destroy upstream_wrap_pthread_mutex_destroy
#define clock_gettime upstream_wrap_clock_gettime

#include "../../src/upstream.c"

#undef clock_gettime
#undef pthread_mutex_destroy
#undef pthread_mutex_unlock
#undef pthread_mutex_lock
#undef pthread_mutex_init

static void test_upstream_resolve_last_resort_unhealthy(void **state) {
    (void)state;
    reset_stubs();

    const char *urls[] = {
#if UPSTREAM_DOH_ENABLED
        "https://dns.google/dns-query",
#endif
#if UPSTREAM_DOT_ENABLED
        "tls://1.1.1.1:853",
#endif
#if UPSTREAM_DOQ_ENABLED
        "quic://9.9.9.9:853",
#endif
    };
    upstream_config_t config = {
        .timeout_ms = 50,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_client_t client;
    assert_int_equal(upstream_client_init(&client, urls, (int)(sizeof(urls) / sizeof(urls[0])), &config), 0);

    g_now_ms = 2000;
    if (client.server_count > 0) {
        client.servers[0].health.healthy = 0;
        client.servers[0].health.last_failure_time = 1500;
    }
    if (client.server_count > 1) {
        client.servers[1].health.healthy = 1;
    }

    g_doh_resolve_rc = -1;
    g_resp_len = 4;
    g_resp_buf[0] = 1;
    g_resp_buf[1] = 2;
    g_resp_buf[2] = 3;
    g_resp_buf[3] = 4;
    g_dot_resolve_rc = -1;
    g_doq_resolve_rc = -1;
#if UPSTREAM_DOH_ENABLED
    g_doh_resolve_rc = 0;
#elif UPSTREAM_DOT_ENABLED
    g_dot_resolve_rc = 0;
#else
    g_doq_resolve_rc = 0;
#endif

    uint8_t q[] = {0xAA};
    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(resolve_any_server(&client, q, sizeof(q), &out, &out_len), 0);
    assert_non_null(out);
    assert_int_equal((int)out_len, 4);
    free(out);

    upstream_client_destroy(&client);
}

static void test_upstream_internal_init_and_switch_edges(void **state) {
    (void)state;
    reset_stubs();

    const char *urls[] = {PRIMARY_TEST_URL};
    upstream_config_t config = {
        .timeout_ms = 50,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };

    upstream_client_t client;
    g_mutex_init_fail = 1;
    assert_int_equal(upstream_client_init(&client, urls, 1, &config), -1);

    reset_stubs();
    assert_int_equal(upstream_client_init(&client, urls, 1, &config), 0);

    upstream_server_t bad_server;
    memset(&bad_server, 0, sizeof(bad_server));
    bad_server.type = (upstream_type_t)99;

    uint8_t q[] = {0x01};
    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(resolve_with_server(&client, &bad_server, config.timeout_ms, q, sizeof(q), &out, &out_len), -1);

#if UPSTREAM_DOH_ENABLED
    bad_server.type = UPSTREAM_TYPE_DOH;
    g_doh_init_rc = -1;
    assert_int_equal(resolve_with_server(&client, &bad_server, config.timeout_ms, q, sizeof(q), &out, &out_len), -1);
#endif

#if UPSTREAM_DOT_ENABLED
    bad_server.type = UPSTREAM_TYPE_DOT;
    g_dot_init_rc = -1;
    assert_int_equal(resolve_with_server(&client, &bad_server, config.timeout_ms, q, sizeof(q), &out, &out_len), -1);
#endif

#if UPSTREAM_DOQ_ENABLED
    bad_server.type = UPSTREAM_TYPE_DOQ;
    g_doq_init_rc = -1;
    assert_int_equal(resolve_with_server(&client, &bad_server, config.timeout_ms, q, sizeof(q), &out, &out_len), -1);
#endif

    upstream_client_destroy(&client);
}

static void test_upstream_parse_and_stats_edges(void **state) {
    (void)state;
    reset_stubs();

    char long_url[400];
    memset(long_url, 'a', sizeof(long_url));
    long_url[0] = '\0';
    strcat(long_url, "https://");
    for (int i = 0; i < 300; i++) {
        strcat(long_url, "a");
    }
    strcat(long_url, "/dns-query");

    upstream_server_t server;
    assert_int_equal(upstream_parse_url(long_url, &server), -1);
    assert_int_equal(upstream_parse_url("tls://", &server), -1);

    upstream_runtime_stats_t stats;
    assert_int_equal(upstream_get_runtime_stats(NULL, NULL), -1);

    upstream_client_t client;
    memset(&client, 0, sizeof(client));
#if UPSTREAM_DOH_ENABLED
    client.doh_client = (upstream_doh_client_t *)(uintptr_t)0x1111;
#endif
#if UPSTREAM_DOT_ENABLED
    client.dot_client = (upstream_dot_client_t *)(uintptr_t)0x2222;
#endif
#if UPSTREAM_DOQ_ENABLED
    client.doq_client = (upstream_doq_client_t *)(uintptr_t)0x3333;
#endif
    assert_int_equal(upstream_get_runtime_stats(&client, &stats), 0);
#if UPSTREAM_DOH_ENABLED
    assert_int_equal(stats.doh_pool_capacity, 3);
#else
    assert_int_equal(stats.doh_pool_capacity, 0);
#endif
#if UPSTREAM_DOT_ENABLED
    assert_int_equal(stats.dot_pool_capacity, 4);
#else
    assert_int_equal(stats.dot_pool_capacity, 0);
#endif
#if UPSTREAM_DOQ_ENABLED
    assert_int_equal(stats.doq_pool_capacity, 5);
#else
    assert_int_equal(stats.doq_pool_capacity, 0);
#endif
}

static void test_upstream_stage_metrics_matrix(void **state) {
    (void)state;

    typedef struct {
        const char *name;
        int iterative_enabled;
        int stage2_rc;
        const char *stage2_reason;
        int stage3_rc;
        const char *stage3_reason;
        uint64_t exp_s2_attempts;
        uint64_t exp_s2_successes;
        uint64_t exp_s2_failures;
        uint64_t exp_s2_cooldowns;
        uint64_t exp_s2_reason_dns;
        uint64_t exp_s2_reason_transport;
        uint64_t exp_s2_reason_cooldown;
        uint64_t exp_s3_attempts;
        uint64_t exp_s3_successes;
        uint64_t exp_s3_failures;
        uint64_t exp_s3_cooldowns;
        uint64_t exp_s3_reason_transport;
        uint64_t exp_s3_reason_cooldown;
    } stage_case_t;

    const stage_case_t cases[] = {
        {
            .name = "s2 cooldown and s3 cooldown",
            .iterative_enabled = 1,
            .stage2_rc = -1,
            .stage2_reason = "cooldown",
            .stage3_rc = -1,
            .stage3_reason = "cooldown",
            .exp_s2_attempts = 1,
            .exp_s2_successes = 0,
            .exp_s2_failures = 1,
            .exp_s2_cooldowns = 1,
            .exp_s2_reason_dns = 0,
            .exp_s2_reason_transport = 0,
            .exp_s2_reason_cooldown = 1,
            .exp_s3_attempts = 0,
            .exp_s3_successes = 0,
            .exp_s3_failures = 0,
            .exp_s3_cooldowns = 0,
            .exp_s3_reason_transport = 0,
            .exp_s3_reason_cooldown = 0,
        },
        {
            .name = "s2 success but retry transport failure",
            .iterative_enabled = 0,
            .stage2_rc = 0,
            .stage2_reason = "ok",
            .stage3_rc = -1,
            .stage3_reason = "cooldown",
            .exp_s2_attempts = 1,
            .exp_s2_successes = 1,
            .exp_s2_failures = 1,
            .exp_s2_cooldowns = 0,
            .exp_s2_reason_dns = 0,
            .exp_s2_reason_transport = 1,
            .exp_s2_reason_cooldown = 0,
            .exp_s3_attempts = 0,
            .exp_s3_successes = 0,
            .exp_s3_failures = 0,
            .exp_s3_cooldowns = 0,
            .exp_s3_reason_transport = 0,
            .exp_s3_reason_cooldown = 0,
        },
        {
            .name = "s2 dns failure then s3 retry transport failure",
            .iterative_enabled = 1,
            .stage2_rc = -1,
            .stage2_reason = "dns_rcode_nonzero",
            .stage3_rc = 0,
            .stage3_reason = "ok",
            .exp_s2_attempts = 1,
            .exp_s2_successes = 0,
            .exp_s2_failures = 1,
            .exp_s2_cooldowns = 0,
            .exp_s2_reason_dns = 1,
            .exp_s2_reason_transport = 0,
            .exp_s2_reason_cooldown = 0,
            .exp_s3_attempts = 1,
            .exp_s3_successes = 1,
            .exp_s3_failures = 1,
            .exp_s3_cooldowns = 0,
            .exp_s3_reason_transport = 1,
            .exp_s3_reason_cooldown = 0,
        },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_stubs();
        g_doh_resolve_rc = -1;
        g_dot_resolve_rc = -1;
        g_doq_resolve_rc = -1;
        g_stage2_rc = cases[i].stage2_rc;
        g_stage2_reason = cases[i].stage2_reason;
        g_stage3_rc = cases[i].stage3_rc;
        g_stage3_reason = cases[i].stage3_reason;

        upstream_config_t cfg = {
            .timeout_ms = 50,
            .pool_size = 1,
            .max_failures_before_unhealthy = 10,
            .unhealthy_backoff_ms = 1000,
            .iterative_bootstrap_enabled = cases[i].iterative_enabled,
        };
        const char *urls[] = {PRIMARY_TEST_URL};
        upstream_client_t client;
        assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

        uint8_t q[] = {0x01, 0x00};
        uint8_t *out = NULL;
        size_t out_len = 0;
        assert_int_equal(resolve_any_server(&client, q, sizeof(q), &out, &out_len), -1);
        free(out);

        upstream_runtime_stats_t stats;
        assert_int_equal(upstream_get_runtime_stats(&client, &stats), 0);

        assert_int_equal(stats.stage2_attempts, cases[i].exp_s2_attempts);
        assert_int_equal(stats.stage2_successes, cases[i].exp_s2_successes);
        assert_int_equal(stats.stage2_failures, cases[i].exp_s2_failures);
        assert_int_equal(stats.stage2_cooldowns, cases[i].exp_s2_cooldowns);
        assert_int_equal(stats.stage2_reason_dns, cases[i].exp_s2_reason_dns);
        assert_int_equal(stats.stage2_reason_transport, cases[i].exp_s2_reason_transport);
        assert_int_equal(stats.stage2_reason_cooldown, cases[i].exp_s2_reason_cooldown);

        assert_int_equal(stats.stage3_attempts, cases[i].exp_s3_attempts);
        assert_int_equal(stats.stage3_successes, cases[i].exp_s3_successes);
        assert_int_equal(stats.stage3_failures, cases[i].exp_s3_failures);
        assert_int_equal(stats.stage3_cooldowns, cases[i].exp_s3_cooldowns);
        assert_int_equal(stats.stage3_reason_transport, cases[i].exp_s3_reason_transport);
        assert_int_equal(stats.stage3_reason_cooldown, cases[i].exp_s3_reason_cooldown);

        upstream_client_destroy(&client);
    }
}

static void test_upstream_transport_timeout_uses_stage2_when_stage1_cache_missing(void **state) {
    (void)state;
    reset_stubs();

    g_doh_resolve_rc = -1;
    g_doh_failure_class = UPSTREAM_FAILURE_CLASS_TIMEOUT;
    g_doh_transport_suppress_ms = 5000;
    g_now_ms = 1000;

    upstream_config_t cfg = {
        .timeout_ms = 2500,
        .pool_size = 1,
        .max_failures_before_unhealthy = 10,
        .unhealthy_backoff_ms = 1000,
        .iterative_bootstrap_enabled = 1,
    };
    const char *urls[] = {PRIMARY_TEST_URL};
    upstream_client_t client;
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    client.servers[0].stage.has_bootstrap_v4 = 1;
    client.servers[0].stage.bootstrap_addr_v4_be = 0x01010101u;
    client.servers[0].stage.bootstrap_expires_at_ms = g_now_ms + 60000;

    uint8_t q[] = {0x12, 0x34};
    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(resolve_any_server(&client, q, sizeof(q), &out, &out_len), -1);
    free(out);

    assert_true(g_stage2_calls >= 1);
    assert_int_equal(g_stage3_calls, 0);

    upstream_runtime_stats_t stats;
    assert_int_equal(upstream_get_runtime_stats(&client, &stats), 0);
    assert_true(stats.stage2_attempts >= 1);
    assert_int_equal(stats.stage3_attempts, 0);

    upstream_client_destroy(&client);
}

static void test_upstream_guard_and_limit_edges(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t cfg = {
        .timeout_ms = 50,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };

    upstream_server_record_success(NULL);

    upstream_server_t s;
    memset(&s, 0, sizeof(s));
    upstream_server_record_failure(NULL, &cfg);
    upstream_server_record_failure(&s, NULL);

    const char *one[] = {PRIMARY_TEST_URL};
    upstream_client_t client;
    assert_int_equal(upstream_client_init(NULL, one, 1, &cfg), -1);
    assert_int_equal(upstream_client_init(&client, NULL, 1, &cfg), -1);
    assert_int_equal(upstream_client_init(&client, one, 0, &cfg), -1);
    assert_int_equal(upstream_client_init(&client, one, 1, NULL), -1);

    const char *many[UPSTREAM_MAX_SERVERS + 4];
    for (size_t i = 0; i < sizeof(many) / sizeof(many[0]); i++) {
        many[i] = PRIMARY_TEST_URL;
    }
    assert_int_equal(upstream_client_init(&client, many, (int)(sizeof(many) / sizeof(many[0])), &cfg), 0);
    assert_int_equal(client.server_count, UPSTREAM_MAX_SERVERS);

    uint8_t q[] = {0x01};
    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(resolve_any_server(NULL, q, sizeof(q), &out, &out_len), -1);
    assert_int_equal(resolve_any_server(&client, NULL, sizeof(q), &out, &out_len), -1);
    assert_int_equal(resolve_any_server(&client, q, 0, &out, &out_len), -1);
    assert_int_equal(resolve_any_server(&client, q, sizeof(q), NULL, &out_len), -1);
    assert_int_equal(resolve_any_server(&client, q, sizeof(q), &out, NULL), -1);

    upstream_client_destroy(NULL);
    upstream_client_destroy(&client);
}

static void test_upstream_ready_state(void **state) {
    (void)state;
    reset_stubs();

    assert_int_equal(upstream_is_ready(NULL), 0);

    upstream_client_t client;
    memset(&client, 0, sizeof(client));
    assert_int_equal(upstream_is_ready(&client), 0);

    client.server_count = 1;
    assert_int_equal(upstream_is_ready(&client), 0);

    client.servers[0].stage.has_bootstrap_v4 = 1;
    assert_int_equal(upstream_is_ready(&client), 1);

    client.servers[0].stage.has_bootstrap_v4 = 0;
    client.servers[0].health.last_success_time = 1;
    assert_int_equal(upstream_is_ready(&client), 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_upstream_resolve_last_resort_unhealthy),
        cmocka_unit_test(test_upstream_internal_init_and_switch_edges),
        cmocka_unit_test(test_upstream_parse_and_stats_edges),
        cmocka_unit_test(test_upstream_stage_metrics_matrix),
        cmocka_unit_test(test_upstream_transport_timeout_uses_stage2_when_stage1_cache_missing),
        cmocka_unit_test(test_upstream_guard_and_limit_edges),
        cmocka_unit_test(test_upstream_ready_state),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
