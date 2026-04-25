#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "errors.h"
#include "upstream.h"

/* Protocol-specific functions under test (implemented in upstream_*.c) */
#if UPSTREAM_DOH_ENABLED
proxy_status_t upstream_doh_client_init(upstream_doh_client_t **client_out, const upstream_config_t *config);
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
    uint64_t *http3_total_out,
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out);
#endif

#if UPSTREAM_DOT_ENABLED
proxy_status_t upstream_dot_client_init(upstream_dot_client_t **client_out, const upstream_config_t *config);
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
#endif

#if UPSTREAM_DOQ_ENABLED
#if UPSTREAM_DOQ_ENABLED
proxy_status_t upstream_doq_client_init(upstream_doq_client_t **client_out, const upstream_config_t *config);
void upstream_doq_client_destroy(upstream_doq_client_t *client);
int upstream_doq_resolve(
    upstream_doq_client_t *client,
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_doq_client_get_pool_stats(
    upstream_doq_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out);
#endif
#endif

#if UPSTREAM_DOH_ENABLED
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
#endif

#if UPSTREAM_DOT_ENABLED
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

static void test_parse_tls_ipv6_authority(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("tls://[2001:db8::1]:853", &server);

    assert_int_equal(result, 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOT);
    assert_string_equal(server.host, "2001:db8::1");
    assert_int_equal(server.port, 853);
}
#endif

static void test_parse_invalid_scheme(void **state) {
    (void)state;

    upstream_server_t server;
    int result = upstream_parse_url("udp://8.8.8.8:53", &server);

    assert_int_equal(result, -1);
}

#if UPSTREAM_DOQ_ENABLED
static void test_parse_quic_default_and_custom_port(void **state) {
    (void)state;

    upstream_server_t server;
    assert_int_equal(upstream_parse_url("quic://dns.example", &server), 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOQ);
    assert_string_equal(server.host, "dns.example");
    assert_int_equal(server.port, 853);

    assert_int_equal(upstream_parse_url("quic://dns.example:8853", &server), 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOQ);
    assert_string_equal(server.host, "dns.example");
    assert_int_equal(server.port, 8853);
}

static void test_parse_quic_ipv6_authority(void **state) {
    (void)state;

    upstream_server_t server;
    assert_int_equal(upstream_parse_url("quic://[2606:4700:4700::1111]", &server), 0);
    assert_int_equal(server.type, UPSTREAM_TYPE_DOQ);
    assert_string_equal(server.host, "2606:4700:4700::1111");
    assert_int_equal(server.port, 853);
}
#endif

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
#if UPSTREAM_DOT_ENABLED
    assert_int_equal(upstream_parse_url("tls://:853", &server), -1);
    assert_int_equal(upstream_parse_url("tls://1.1.1.1:0", &server), -1);
    assert_int_equal(upstream_parse_url("tls://1.1.1.1:853/path", &server), -1);
    assert_int_equal(upstream_parse_url("tls://2001:db8::1:853", &server), -1);
#endif
#if UPSTREAM_DOQ_ENABLED
    assert_int_equal(upstream_parse_url("doq://dns.example:853", &server), -1);
    assert_int_equal(upstream_parse_url("quic://dns.example:853/path", &server), -1);
    assert_int_equal(upstream_parse_url("quic://[2606:4700:4700::1111", &server), -1);
#endif
}

static void test_client_init_mixed_urls(void **state) {
    (void)state;

    const char *urls[] = {
        "bad://invalid",
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
        .timeout_ms = 2000,
        .pool_size = 4,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_client_t client;

    int result = upstream_client_init(&client, urls, (int)(sizeof(urls) / sizeof(urls[0])), &config);

    assert_int_equal(result, 0);
    int expected = 0;
#if UPSTREAM_DOH_ENABLED
    expected++;
#endif
#if UPSTREAM_DOT_ENABLED
    expected++;
#endif
#if UPSTREAM_DOQ_ENABLED
    expected++;
#endif
    assert_int_equal(client.server_count, expected);

    int idx = 0;
#if UPSTREAM_DOH_ENABLED
    assert_int_equal(client.servers[idx++].type, UPSTREAM_TYPE_DOH);
#endif
#if UPSTREAM_DOT_ENABLED
    assert_int_equal(client.servers[idx++].type, UPSTREAM_TYPE_DOT);
#endif
#if UPSTREAM_DOQ_ENABLED
    assert_int_equal(client.servers[idx++].type, UPSTREAM_TYPE_DOQ);
#endif

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

    const char *urls[] = {
#if UPSTREAM_DOH_ENABLED
        "https://dns.google/dns-query"
#elif UPSTREAM_DOT_ENABLED
        "tls://1.1.1.1:853"
#else
        "quic://9.9.9.9:853"
#endif
    };
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
    server.stage.last_failure_class = UPSTREAM_FAILURE_CLASS_TRANSPORT;

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
    server.stage.last_failure_class = UPSTREAM_FAILURE_CLASS_TRANSPORT;

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

    const char *urls[] = {
#if UPSTREAM_DOH_ENABLED
        "https://dns.google/dns-query"
#elif UPSTREAM_DOT_ENABLED
        "tls://1.1.1.1:853"
#else
        "quic://9.9.9.9:853"
#endif
    };
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
    assert_int_equal(stats.doq_pool_capacity, 0);
    assert_int_equal(stats.doq_pool_in_use, 0);

    upstream_client_destroy(&client);
}

#if UPSTREAM_DOH_ENABLED
static void test_doh_protocol_guard_paths(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_doh_client_t *client = NULL;
    assert_int_equal(upstream_doh_client_init(&client, &config), PROXY_OK);
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
    uint64_t h3 = 1, h2 = 1, h1 = 1, other = 1;
    assert_int_equal(upstream_doh_client_get_pool_stats(NULL, &cap, &in_use, &h3, &h2, &h1, &other), -1);
    assert_int_equal(h3, 0);
    assert_int_equal(cap, 0);
    assert_int_equal(in_use, 0);
    assert_int_equal(h2, 0);
    assert_int_equal(h1, 0);
    assert_int_equal(other, 0);

    upstream_doh_client_destroy(client);
}
#endif

#if UPSTREAM_DOT_ENABLED
static void test_dot_protocol_guard_paths(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_dot_client_t *client = NULL;
    assert_int_equal(upstream_dot_client_init(&client, &config), PROXY_OK);
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
#endif

static void test_protocol_client_init_and_destroy_guards(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };

#if UPSTREAM_DOH_ENABLED
    upstream_doh_client_t *doh_client = NULL;
#endif
#if UPSTREAM_DOT_ENABLED
    upstream_dot_client_t *dot_client = NULL;
#endif
#if UPSTREAM_DOQ_ENABLED
    upstream_doq_client_t *doq_client = NULL;
#endif

#if UPSTREAM_DOH_ENABLED
    assert_int_equal(upstream_doh_client_init(NULL, &config), PROXY_ERR_INVALID_ARG);
    assert_int_equal(upstream_doh_client_init(&doh_client, NULL), PROXY_ERR_INVALID_ARG);
#endif
#if UPSTREAM_DOT_ENABLED
    assert_int_equal(upstream_dot_client_init(NULL, &config), PROXY_ERR_INVALID_ARG);
    assert_int_equal(upstream_dot_client_init(&dot_client, NULL), PROXY_ERR_INVALID_ARG);
#endif
#if UPSTREAM_DOQ_ENABLED
    assert_int_equal(upstream_doq_client_init(NULL, &config), PROXY_ERR_INVALID_ARG);
    assert_int_equal(upstream_doq_client_init(&doq_client, NULL), PROXY_ERR_INVALID_ARG);
#endif

#if UPSTREAM_DOH_ENABLED
    assert_int_equal(upstream_doh_client_init(&doh_client, &config), PROXY_OK);
#endif
#if UPSTREAM_DOT_ENABLED
    assert_int_equal(upstream_dot_client_init(&dot_client, &config), PROXY_OK);
#endif
#if UPSTREAM_DOQ_ENABLED
    assert_int_equal(upstream_doq_client_init(&doq_client, &config), PROXY_OK);
#endif

    int cap = 0;
    int in_use = 0;
#if UPSTREAM_DOT_ENABLED || UPSTREAM_DOQ_ENABLED
    int alive = 0;
#endif
#if UPSTREAM_DOH_ENABLED
    uint64_t h3 = 0, h2 = 0, h1 = 0, other = 0;
#endif

#if UPSTREAM_DOH_ENABLED
    assert_int_equal(upstream_doh_client_get_pool_stats(doh_client, &cap, &in_use, &h3, &h2, &h1, &other), 0);
    assert_true(cap >= 1);
    assert_int_equal(in_use, 0);
#endif

#if UPSTREAM_DOT_ENABLED
    assert_int_equal(upstream_dot_client_get_pool_stats(dot_client, &cap, &in_use, &alive), 0);
    assert_true(cap >= 1);
    assert_int_equal(in_use, 0);
    assert_int_equal(alive, 0);
#endif

#if UPSTREAM_DOQ_ENABLED
    assert_int_equal(upstream_doq_client_get_pool_stats(doq_client, &cap, &in_use, &alive), 0);
    assert_true(cap >= 1);
    assert_int_equal(in_use, 0);
    assert_int_equal(alive, 0);
#endif

#if UPSTREAM_DOH_ENABLED
    upstream_doh_client_destroy(doh_client);
#endif
#if UPSTREAM_DOT_ENABLED
    upstream_dot_client_destroy(dot_client);
#endif
#if UPSTREAM_DOQ_ENABLED
    upstream_doq_client_destroy(doq_client);
#endif

#if UPSTREAM_DOH_ENABLED
    upstream_doh_client_destroy(NULL);
#endif
#if UPSTREAM_DOT_ENABLED
    upstream_dot_client_destroy(NULL);
#endif
#if UPSTREAM_DOQ_ENABLED
    upstream_doq_client_destroy(NULL);
#endif
}

#if UPSTREAM_DOQ_ENABLED
static void test_doq_protocol_guard_paths(void **state) {
    (void)state;

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_doq_client_t *client = NULL;
    assert_int_equal(upstream_doq_client_init(&client, &config), PROXY_OK);
    assert_non_null(client);

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOH;

    uint8_t query[4] = {0, 1, 2, 3};
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    assert_int_equal(upstream_doq_resolve(NULL, &server, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_doq_resolve(client, NULL, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_doq_resolve(client, &server, 100, NULL, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal(upstream_doq_resolve(client, &server, 100, query, 0, &resp, &resp_len), -1);
    assert_int_equal(upstream_doq_resolve(client, &server, 100, query, sizeof(query), NULL, &resp_len), -1);
    assert_int_equal(upstream_doq_resolve(client, &server, 100, query, sizeof(query), &resp, NULL), -1);

    server.type = UPSTREAM_TYPE_DOQ;
    assert_int_equal(upstream_doq_resolve(client, &server, 100, query, sizeof(query), &resp, &resp_len), -1);

    int cap = 1;
    int in_use = 1;
    int alive = 1;
    assert_int_equal(upstream_doq_client_get_pool_stats(NULL, &cap, &in_use, &alive), -1);
    assert_int_equal(cap, 0);
    assert_int_equal(in_use, 0);
    assert_int_equal(alive, 0);

    upstream_doq_client_destroy(client);
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#if UPSTREAM_DOH_ENABLED
        cmocka_unit_test(test_parse_https_default_port),
        cmocka_unit_test(test_parse_https_custom_port),
#endif
#if UPSTREAM_DOT_ENABLED
        cmocka_unit_test(test_parse_tls_default_port),
        cmocka_unit_test(test_parse_tls_custom_port),
        cmocka_unit_test(test_parse_tls_ipv6_authority),
#endif
        cmocka_unit_test(test_parse_invalid_scheme),
#if UPSTREAM_DOQ_ENABLED
        cmocka_unit_test(test_parse_quic_default_and_custom_port),
        cmocka_unit_test(test_parse_quic_ipv6_authority),
#endif
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
#if UPSTREAM_DOH_ENABLED
        cmocka_unit_test(test_doh_protocol_guard_paths),
#endif
#if UPSTREAM_DOT_ENABLED
        cmocka_unit_test(test_dot_protocol_guard_paths),
#endif
#if UPSTREAM_DOQ_ENABLED
        cmocka_unit_test(test_doq_protocol_guard_paths),
#endif
        cmocka_unit_test(test_protocol_client_init_and_destroy_guards),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
