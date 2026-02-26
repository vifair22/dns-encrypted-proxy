#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cache.h"
#include "upstream.h"
#include "metrics.h"

static size_t g_stub_cache_capacity = 0;
static size_t g_stub_cache_entries = 0;
static uint64_t g_stub_cache_evictions = 0;
static uint64_t g_stub_cache_expirations = 0;
static size_t g_stub_cache_bytes = 0;
static upstream_runtime_stats_t g_stub_runtime_stats;
static proxy_metrics_t g_test_metrics;
static int g_fail_socket = 0;
static int g_fail_bind = 0;
static int g_fail_listen = 0;
static int g_fail_pthread_create = 0;
static int g_fail_send = 0;

static int metrics_wrap_socket(int domain, int type, int protocol) {
    if (g_fail_socket) {
        errno = EMFILE;
        return -1;
    }
    return socket(domain, type, protocol);
}

static int metrics_wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    if (g_fail_bind) {
        errno = EADDRINUSE;
        return -1;
    }
    return bind(fd, addr, len);
}

static int metrics_wrap_listen(int fd, int backlog) {
    if (g_fail_listen) {
        errno = EINVAL;
        return -1;
    }
    return listen(fd, backlog);
}

static int metrics_wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    if (g_fail_pthread_create) {
        return -1;
    }
    return pthread_create(thread, attr, start_routine, arg);
}

static ssize_t metrics_wrap_send(int fd, const void *buf, size_t len, int flags) {
    if (g_fail_send) {
        errno = EPIPE;
        return -1;
    }
    return send(fd, buf, len, flags);
}

void dns_cache_get_stats(dns_cache_t *cache, size_t *capacity_out, size_t *entries_out) {
    (void)cache;
    if (capacity_out != NULL) {
        *capacity_out = g_stub_cache_capacity;
    }
    if (entries_out != NULL) {
        *entries_out = g_stub_cache_entries;
    }
}

void dns_cache_get_counters(dns_cache_t *cache, uint64_t *evictions_out, uint64_t *expirations_out, size_t *bytes_in_use_out) {
    (void)cache;
    if (evictions_out != NULL) {
        *evictions_out = g_stub_cache_evictions;
    }
    if (expirations_out != NULL) {
        *expirations_out = g_stub_cache_expirations;
    }
    if (bytes_in_use_out != NULL) {
        *bytes_in_use_out = g_stub_cache_bytes;
    }
}

int upstream_get_runtime_stats(upstream_client_t *client, upstream_runtime_stats_t *stats_out) {
    (void)client;
    if (stats_out == NULL) {
        return -1;
    }
    *stats_out = g_stub_runtime_stats;
    return 0;
}

#define socket metrics_wrap_socket
#define bind metrics_wrap_bind
#define listen metrics_wrap_listen
#define pthread_create metrics_wrap_pthread_create
#define send metrics_wrap_send
#include "../../src/metrics.c"
#undef send
#undef pthread_create
#undef listen
#undef bind
#undef socket

static void test_appendf_and_escape_guards(void **state) {
    (void)state;

    char out[8];
    size_t off = 0;

    assert_int_equal(appendf(NULL, sizeof(out), &off, "x"), -1);
    assert_int_equal(appendf(out, sizeof(out), NULL, "x"), -1);
    assert_int_equal(appendf(out, sizeof(out), &off, NULL), -1);

    off = sizeof(out);
    assert_int_equal(appendf(out, sizeof(out), &off, "x"), -1);

    off = 0;
    assert_int_equal(appendf(out, sizeof(out), &off, "123456789"), -1);

    char escaped[8];
    escape_label_value(NULL, escaped, sizeof(escaped));
    assert_string_equal(escaped, "");

    escape_label_value("a\"\\\n", escaped, sizeof(escaped));
    assert_true(strstr(escaped, "\\") != NULL);
}

static void test_build_metrics_body_guards_and_idle_clamp(void **state) {
    (void)state;

    proxy_metrics_t m;
    metrics_init(&m);

    assert_int_equal(build_metrics_body(NULL, NULL, 0), -1);

    g_stub_cache_capacity = 10;
    g_stub_cache_entries = 2;
    g_stub_cache_evictions = 5;
    g_stub_cache_expirations = 3;
    g_stub_cache_bytes = 100;

    memset(&g_stub_runtime_stats, 0, sizeof(g_stub_runtime_stats));
    g_stub_runtime_stats.doh_pool_capacity = 1;
    g_stub_runtime_stats.doh_pool_in_use = 5;
    g_stub_runtime_stats.dot_pool_capacity = 2;
    g_stub_runtime_stats.dot_pool_in_use = 7;

    dns_cache_t dummy_cache;
    memset(&dummy_cache, 0, sizeof(dummy_cache));
    upstream_client_t dummy_upstream;
    memset(&dummy_upstream, 0, sizeof(dummy_upstream));

    g_cache = &dummy_cache;
    g_upstream = &dummy_upstream;

    char body[32768];
    int len = build_metrics_body(&m, body, sizeof(body));
    assert_true(len > 0);
    assert_non_null(strstr(body, "dns_encrypted_proxy_doh_pool_idle 0"));
    assert_non_null(strstr(body, "dns_encrypted_proxy_dot_pool_idle 0"));

    g_cache = NULL;
    g_upstream = NULL;
}

static void test_append_upstream_metrics_paths(void **state) {
    (void)state;

    size_t off = 0;
    char out[64];
    assert_int_equal(append_upstream_metrics(out, sizeof(out), &off), -1);

    upstream_client_t upstream;
    memset(&upstream, 0, sizeof(upstream));
    upstream.server_count = 1;
    upstream.servers[0].type = UPSTREAM_TYPE_DOH;
    memset(upstream.servers[0].url, 'x', sizeof(upstream.servers[0].url) - 1);
    upstream.servers[0].url[sizeof(upstream.servers[0].url) - 1] = '\0';

    g_upstream = &upstream;
    off = 0;
    char bigger[512];
    assert_int_equal(append_upstream_metrics(bigger, sizeof(bigger), &off), -1);

    g_upstream = NULL;
}

static void test_handle_client_error_paths(void **state) {
    (void)state;

    metrics_init(&g_test_metrics);
    g_metrics = &g_test_metrics;

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    const char *req_404 = "GET /x HTTP/1.1\r\n\r\n";
    assert_int_equal((int)write(sv[1], req_404, strlen(req_404)), (int)strlen(req_404));
    shutdown(sv[1], SHUT_WR);
    handle_client(sv[0]);
    close(sv[0]);
    close(sv[1]);

    assert_true((uint64_t)atomic_load(&g_test_metrics.metrics_http_responses_4xx_total) >= 1);

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    const char *req_metrics = "GET /metrics HTTP/1.1\r\n\r\n";
    assert_int_equal((int)write(sv[1], req_metrics, strlen(req_metrics)), (int)strlen(req_metrics));
    shutdown(sv[1], SHUT_WR);

    g_metrics = NULL;
    handle_client(sv[0]);
    close(sv[0]);
    close(sv[1]);

    g_metrics = &g_test_metrics;
}

static void test_metrics_server_start_failure_paths(void **state) {
    (void)state;

    dns_cache_t dummy_cache;
    memset(&dummy_cache, 0, sizeof(dummy_cache));

    metrics_init(&g_test_metrics);

    g_fail_socket = 1;
    assert_int_equal(metrics_server_start(&g_test_metrics, &dummy_cache, NULL, 9099), -1);
    g_fail_socket = 0;

    g_fail_bind = 1;
    assert_int_equal(metrics_server_start(&g_test_metrics, &dummy_cache, NULL, 9099), -1);
    g_fail_bind = 0;

    g_fail_listen = 1;
    assert_int_equal(metrics_server_start(&g_test_metrics, &dummy_cache, NULL, 9099), -1);
    g_fail_listen = 0;

    g_fail_pthread_create = 1;
    assert_int_equal(metrics_server_start(&g_test_metrics, &dummy_cache, NULL, 9099), -1);
    g_fail_pthread_create = 0;
}

static void test_handle_client_500_write_failure_path(void **state) {
    (void)state;

    metrics_init(&g_test_metrics);
    g_metrics = &g_test_metrics;

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    const char *req_metrics = "GET /metrics HTTP/1.1\r\n\r\n";
    assert_int_equal((int)write(sv[1], req_metrics, strlen(req_metrics)), (int)strlen(req_metrics));
    shutdown(sv[1], SHUT_WR);

    g_fail_send = 1;
    handle_client(sv[0]);
    g_fail_send = 0;

    close(sv[0]);
    close(sv[1]);

    assert_true((uint64_t)atomic_load(&g_test_metrics.metrics_http_responses_5xx_total) >= 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_appendf_and_escape_guards),
        cmocka_unit_test(test_build_metrics_body_guards_and_idle_clamp),
        cmocka_unit_test(test_append_upstream_metrics_paths),
        cmocka_unit_test(test_handle_client_error_paths),
        cmocka_unit_test(test_metrics_server_start_failure_paths),
        cmocka_unit_test(test_handle_client_500_write_failure_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
