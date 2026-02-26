#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "upstream.h"

/* Protocol-specific functions under test (implemented in upstream_doh.c/upstream_dot.c) */
int upstream_doh_client_init(upstream_doh_client_t **client_out, const upstream_config_t *config);
void upstream_doh_client_destroy(upstream_doh_client_t *client);
int upstream_doh_resolve(
    upstream_doh_client_t *client,
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_doh_client_get_pool_stats(
    upstream_doh_client_t *client,
    int *capacity_out,
    int *in_use_out,
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out);

int upstream_dot_client_init(upstream_dot_client_t **client_out, const upstream_config_t *config);
void upstream_dot_client_destroy(upstream_dot_client_t *client);
int upstream_dot_resolve(
    upstream_dot_client_t *client,
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_dot_client_get_pool_stats(
    upstream_dot_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out);

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

static void test_parse_invalid_host_or_port(void **state) {
    (void)state;

    upstream_server_t server;
    assert_int_equal(upstream_parse_url("https:///dns-query", &server), -1);
    assert_int_equal(upstream_parse_url("https://dns.google:0/dns-query", &server), -1);
    assert_int_equal(upstream_parse_url("https://dns.google:70000/dns-query", &server), -1);
    assert_int_equal(upstream_parse_url("tls://:853", &server), -1);
    assert_int_equal(upstream_parse_url("tls://1.1.1.1:0", &server), -1);
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

static void test_client_init_all_invalid_urls_fails(void **state) {
    (void)state;

    const char *urls[] = {
        "bad://invalid",
        "udp://8.8.8.8:53",
        "https:///dns-query"
    };
    upstream_config_t config = {
        .timeout_ms = 2000,
        .pool_size = 2,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_client_t client;

    assert_int_equal(upstream_client_init(&client, urls, 3, &config), -1);
}

static void test_client_init_applies_default_policy_values(void **state) {
    (void)state;

    const char *urls[] = {"https://dns.google/dns-query"};
    upstream_config_t config = {
        .timeout_ms = 1000,
        .pool_size = 1,
        .max_failures_before_unhealthy = 0,
        .unhealthy_backoff_ms = 0,
    };
    upstream_client_t client;

    assert_int_equal(upstream_client_init(&client, urls, 1, &config), 0);
    assert_int_equal(client.config.max_failures_before_unhealthy, 3);
    assert_int_equal(client.config.unhealthy_backoff_ms, 10000);
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

static void test_should_skip_null_inputs(void **state) {
    (void)state;

    upstream_server_t server;
    upstream_config_t config;
    memset(&server, 0, sizeof(server));
    memset(&config, 0, sizeof(config));

    assert_int_equal(upstream_server_should_skip(NULL, &config), 1);
    assert_int_equal(upstream_server_should_skip(&server, NULL), 1);
}

static void test_runtime_stats_api_guards_and_basics(void **state) {
    (void)state;

    upstream_runtime_stats_t stats;
    assert_int_equal(upstream_get_runtime_stats(NULL, NULL), -1);
    assert_int_equal(upstream_get_runtime_stats(NULL, &stats), -1);

    const char *urls[] = {"https://dns.google/dns-query"};
    upstream_config_t config = {
        .timeout_ms = 1000,
        .pool_size = 2,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_client_t client;
    assert_int_equal(upstream_client_init(&client, urls, 1, &config), 0);

    assert_int_equal(upstream_get_runtime_stats(&client, &stats), 0);
    assert_int_equal(stats.doh_pool_capacity, 0);
    assert_int_equal(stats.doh_pool_in_use, 0);
    assert_int_equal(stats.dot_pool_capacity, 0);
    assert_int_equal(stats.dot_pool_in_use, 0);

    upstream_client_destroy(&client);
}

static void test_doh_protocol_guard_paths(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_doh_client_t *client = NULL;
    assert_int_equal(upstream_doh_client_init(&client, &config), 0);
    assert_non_null(client);

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOT;
    strcpy(server.url, "tls://1.1.1.1:853");

    uint8_t query[] = {0x00};
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    assert_int_equal(upstream_doh_resolve(NULL, &server, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_doh_resolve(client, NULL, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_doh_resolve(client, &server, 100, NULL, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_doh_resolve(client, &server, 100, query, 0, &resp, &resp_len), -1);
    assert_int_equal(upstream_doh_resolve(client, &server, 100, query, sizeof(query), NULL, &resp_len), -1);
    assert_int_equal(upstream_doh_resolve(client, &server, 100, query, sizeof(query), &resp, NULL), -1);
    assert_int_equal(upstream_doh_resolve(client, &server, 100, query, sizeof(query), &resp, &resp_len), -1);

    int cap = 1;
    int in_use = 1;
    uint64_t h2 = 1, h1 = 1, other = 1;
    assert_int_equal(upstream_doh_client_get_pool_stats(NULL, &cap, &in_use, &h2, &h1, &other), -1);
    assert_int_equal(cap, 0);
    assert_int_equal(in_use, 0);
    assert_int_equal(h2, 0);
    assert_int_equal(h1, 0);
    assert_int_equal(other, 0);

    upstream_doh_client_destroy(client);
}

static void test_dot_protocol_guard_paths(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_dot_client_t *client = NULL;
    assert_int_equal(upstream_dot_client_init(&client, &config), 0);
    assert_non_null(client);

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOH;
    strcpy(server.host, "127.0.0.1");
    server.port = 443;

    uint8_t query[4] = {0, 1, 2, 3};
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    assert_int_equal(upstream_dot_resolve(NULL, &server, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_dot_resolve(client, NULL, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_dot_resolve(client, &server, 100, NULL, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_dot_resolve(client, &server, 100, query, 0, &resp, &resp_len), -1);
    assert_int_equal(upstream_dot_resolve(client, &server, 100, query, sizeof(query), NULL, &resp_len), -1);
    assert_int_equal(upstream_dot_resolve(client, &server, 100, query, sizeof(query), &resp, NULL), -1);
    assert_int_equal(upstream_dot_resolve(client, &server, 100, query, sizeof(query), &resp, &resp_len), -1);

    server.type = UPSTREAM_TYPE_DOT;
    server.port = 853;
    size_t oversized_len = 65534; /* > DOT_MAX_MESSAGE_SIZE - 2 */
    uint8_t *oversized_query = malloc(oversized_len);
    assert_non_null(oversized_query);
    memset(oversized_query, 0xAB, oversized_len);
    assert_int_equal(upstream_dot_resolve(client, &server, 100, oversized_query, oversized_len, &resp, &resp_len), -1);
    free(oversized_query);

    int cap = 1;
    int in_use = 1;
    int alive = 1;
    assert_int_equal(upstream_dot_client_get_pool_stats(NULL, &cap, &in_use, &alive), -1);
    assert_int_equal(cap, 0);
    assert_int_equal(in_use, 0);
    assert_int_equal(alive, 0);

    upstream_dot_client_destroy(client);
}

static void test_protocol_client_init_and_destroy_guards(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };

    upstream_doh_client_t *doh_client = NULL;
    upstream_dot_client_t *dot_client = NULL;

    assert_int_equal(upstream_doh_client_init(NULL, &config), -1);
    assert_int_equal(upstream_doh_client_init(&doh_client, NULL), -1);
    assert_int_equal(upstream_dot_client_init(NULL, &config), -1);
    assert_int_equal(upstream_dot_client_init(&dot_client, NULL), -1);

    assert_int_equal(upstream_doh_client_init(&doh_client, &config), 0);
    assert_int_equal(upstream_dot_client_init(&dot_client, &config), 0);

    int cap = 0;
    int in_use = 0;
    int alive = 0;
    uint64_t h2 = 0, h1 = 0, other = 0;

    assert_int_equal(upstream_doh_client_get_pool_stats(doh_client, &cap, &in_use, &h2, &h1, &other), 0);
    assert_true(cap >= 1);
    assert_int_equal(in_use, 0);

    assert_int_equal(upstream_dot_client_get_pool_stats(dot_client, &cap, &in_use, &alive), 0);
    assert_true(cap >= 1);
    assert_int_equal(in_use, 0);
    assert_int_equal(alive, 0);

    upstream_doh_client_destroy(doh_client);
    upstream_dot_client_destroy(dot_client);

    upstream_doh_client_destroy(NULL);
    upstream_dot_client_destroy(NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_https_default_port),
        cmocka_unit_test(test_parse_https_custom_port),
        cmocka_unit_test(test_parse_tls_default_port),
        cmocka_unit_test(test_parse_tls_custom_port),
        cmocka_unit_test(test_parse_invalid_scheme),
        cmocka_unit_test(test_parse_invalid_parameters),
        cmocka_unit_test(test_parse_invalid_host_or_port),
        cmocka_unit_test(test_client_init_mixed_urls),
        cmocka_unit_test(test_client_init_all_invalid_urls_fails),
        cmocka_unit_test(test_client_init_applies_default_policy_values),
        cmocka_unit_test(test_record_failure_marks_unhealthy),
        cmocka_unit_test(test_backoff_elapsed_allows_retry),
        cmocka_unit_test(test_record_success_resets_failures),
        cmocka_unit_test(test_should_skip_null_inputs),
        cmocka_unit_test(test_runtime_stats_api_guards_and_basics),
        cmocka_unit_test(test_doh_protocol_guard_paths),
        cmocka_unit_test(test_dot_protocol_guard_paths),
        cmocka_unit_test(test_protocol_client_init_and_destroy_guards),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
