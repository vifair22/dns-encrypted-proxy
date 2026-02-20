#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>

#include "upstream.h"

static void test_parse_https_default_port(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("https://dns.google/dns-query", &server);

    assert_int_equal(result, 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOH);
    assert_string_equal(server.host, "dns.google");
    assert_int_equal(server.port, 443);
    assert_int_equal(server.health.healthy, 1);
}

static void test_parse_https_custom_port(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("https://example.com:8443/dns-query", &server);

    assert_int_equal(result, 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOH);
    assert_string_equal(server.host, "example.com");
    assert_int_equal(server.port, 8443);
}

static void test_parse_tls_default_port(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("tls://1.1.1.1", &server);

    assert_int_equal(result, 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOT);
    assert_string_equal(server.host, "1.1.1.1");
    assert_int_equal(server.port, 853);
    assert_int_equal(server.health.healthy, 1);
}

static void test_parse_tls_custom_port(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("tls://9.9.9.9:9953", &server);

    assert_int_equal(result, 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOT);
    assert_string_equal(server.host, "9.9.9.9");
    assert_int_equal(server.port, 9953);
}

static void test_parse_invalid_scheme(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("udp://8.8.8.8:53", &server);

    assert_int_equal(result, -1);
}

static void test_parse_invalid_parameters(void **state) {
    (void)state;

    upstream_server_t server;
    assert_int_equal(upstream_parse_url(NULL, &server), -1);
    assert_int_equal(upstream_parse_url("https://dns.google/dns-query", NULL), -1);
}

static void test_client_init_mixed_urls(void **state) {
    (void)state;

    const char *urls[] = {
        "bad://invalid",
        "https://dns.google/dns-query",
        "tls://1.1.1.1:853"
    };
    upstream_config_t config = {
        .timeout_ms = 2000,
        .pool_size = 4,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_client_t client;

    int result = upstream_client_init(&client, urls, 3, &config);

    assert_int_equal(result, 0);
    assert_int_equal(client.server_count, 2);
    assert_int_equal(client.servers[0].type, UPSTREAM_TYPE_DOH);
    assert_int_equal(client.servers[1].type, UPSTREAM_TYPE_DOT);

    upstream_client_destroy(&client);
}

static void test_record_failure_marks_unhealthy(void **state) {
    (void)state;

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.health.healthy = 1;

    upstream_config_t config = {
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 60000,
    };

    upstream_server_record_failure(&server, &config);
    assert_int_equal(server.health.healthy, 1);
    assert_int_equal(server.health.consecutive_failures, 1);

    upstream_server_record_failure(&server, &config);
    assert_int_equal(server.health.healthy, 0);
    assert_int_equal(server.health.consecutive_failures, 2);
    assert_int_equal(server.health.total_queries, 2);
    assert_int_equal(server.health.total_failures, 2);

    assert_int_equal(upstream_server_should_skip(&server, &config), 1);
}

static void test_backoff_elapsed_allows_retry(void **state) {
    (void)state;

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.health.healthy = 1;

    upstream_config_t failure_config = {
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_server_record_failure(&server, &failure_config);
    assert_int_equal(server.health.healthy, 0);

    upstream_config_t retry_config = {
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 0,
    };
    assert_int_equal(upstream_server_should_skip(&server, &retry_config), 0);
}

static void test_record_success_resets_failures(void **state) {
    (void)state;

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.health.healthy = 0;
    server.health.consecutive_failures = 5;
    server.health.total_queries = 10;

    upstream_server_record_success(&server);

    assert_int_equal(server.health.healthy, 1);
    assert_int_equal(server.health.consecutive_failures, 0);
    assert_int_equal(server.health.total_queries, 11);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_https_default_port),
        cmocka_unit_test(test_parse_https_custom_port),
        cmocka_unit_test(test_parse_tls_default_port),
        cmocka_unit_test(test_parse_tls_custom_port),
        cmocka_unit_test(test_parse_invalid_scheme),
        cmocka_unit_test(test_parse_invalid_parameters),
        cmocka_unit_test(test_client_init_mixed_urls),
        cmocka_unit_test(test_record_failure_marks_unhealthy),
        cmocka_unit_test(test_backoff_elapsed_allows_retry),
        cmocka_unit_test(test_record_success_resets_failures),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
