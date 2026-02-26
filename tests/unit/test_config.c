/*
 * Unit tests for config.c
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "test_helpers.h"

/*
 * Test: config_load with defaults (no config file, no env vars)
 */
static void test_config_defaults(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    proxy_config_t config;
    /* Use a non-existent file so only defaults apply */
    int result = config_load(&config, "/nonexistent/path/config.conf");
    
    assert_int_equal(result, 0);
    assert_string_equal(config.listen_addr, "0.0.0.0");
    assert_int_equal(config.listen_port, 53);
    assert_int_equal(config.upstream_timeout_ms, 2500);
    assert_int_equal(config.upstream_pool_size, 6);
    assert_int_equal(config.cache_capacity, 1024);
    assert_int_equal(config.tcp_idle_timeout_ms, 10000);
    assert_int_equal(config.tcp_max_clients, 256);
    assert_int_equal(config.tcp_max_queries_per_conn, 0);
    assert_int_equal(config.metrics_enabled, 1);
    assert_int_equal(config.metrics_port, 9090);
    assert_int_equal(config.upstream_count, 2);
    assert_string_equal(config.upstream_urls[0], "https://cloudflare-dns.com/dns-query");
    assert_string_equal(config.upstream_urls[1], "https://dns.google/dns-query");
}

/*
 * Test: config_load from a file
 */
static void test_config_file_parse(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    const char *config_content =
        "# Test config file\n"
        "listen_addr=127.0.0.1\n"
        "listen_port=5353\n"
        "upstream_timeout_ms=5000\n"
        "upstream_pool_size=10\n"
        "cache_capacity=2048\n"
        "upstreams=https://custom.dns/query\n"
        "tcp_idle_timeout_ms=30000\n"
        "tcp_max_clients=512\n"
        "tcp_max_queries_per_conn=100\n"
        "metrics_enabled=0\n"
        "metrics_port=8080\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    proxy_config_t config;
    int result = config_load(&config, temp_file);
    
    assert_int_equal(result, 0);
    assert_string_equal(config.listen_addr, "127.0.0.1");
    assert_int_equal(config.listen_port, 5353);
    assert_int_equal(config.upstream_timeout_ms, 5000);
    assert_int_equal(config.upstream_pool_size, 10);
    assert_int_equal(config.cache_capacity, 2048);
    assert_int_equal(config.tcp_idle_timeout_ms, 30000);
    assert_int_equal(config.tcp_max_clients, 512);
    assert_int_equal(config.tcp_max_queries_per_conn, 100);
    assert_int_equal(config.metrics_enabled, 0);
    assert_int_equal(config.metrics_port, 8080);
    assert_int_equal(config.upstream_count, 1);
    assert_string_equal(config.upstream_urls[0], "https://custom.dns/query");
    
    remove_temp_file(temp_file);
}

/*
 * Test: environment variables override config file
 */
static void test_config_env_override(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    /* Create config file with some values */
    const char *config_content =
        "listen_addr=192.168.1.1\n"
        "listen_port=5353\n"
        "cache_capacity=500\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    /* Set environment variables that should override file values */
    setenv("LISTEN_ADDR", "10.0.0.1", 1);
    setenv("LISTEN_PORT", "8053", 1);
    setenv("CACHE_CAPACITY", "4096", 1);
    
    proxy_config_t config;
    int result = config_load(&config, temp_file);
    
    assert_int_equal(result, 0);
    /* These should be overridden by env vars */
    assert_string_equal(config.listen_addr, "10.0.0.1");
    assert_int_equal(config.listen_port, 8053);
    assert_int_equal(config.cache_capacity, 4096);
    
    remove_temp_file(temp_file);
    clear_config_env_vars();
}

/*
 * Test: multiple upstream URLs parsing
 */
static void test_config_multiple_upstreams(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    const char *config_content =
        "upstreams=https://dns1.example/query, tls://1.1.1.1:853, https://dns3.example/query\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    proxy_config_t config;
    int result = config_load(&config, temp_file);
    
    assert_int_equal(result, 0);
    assert_int_equal(config.upstream_count, 3);
    assert_string_equal(config.upstream_urls[0], "https://dns1.example/query");
    assert_string_equal(config.upstream_urls[1], "tls://1.1.1.1:853");
    assert_string_equal(config.upstream_urls[2], "https://dns3.example/query");
    
    remove_temp_file(temp_file);
}

/*
 * Test: config with whitespace and comments
 */
static void test_config_whitespace_comments(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    const char *config_content =
        "  # Comment at start\n"
        "\n"
        "  listen_port = 5353  \n"
        "# Another comment\n"
        "   cache_capacity=2048   \n"
        "\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    proxy_config_t config;
    int result = config_load(&config, temp_file);
    
    assert_int_equal(result, 0);
    assert_int_equal(config.listen_port, 5353);
    assert_int_equal(config.cache_capacity, 2048);
    
    remove_temp_file(temp_file);
}

/*
 * Test: config with invalid integer values falls back to defaults
 */
static void test_config_invalid_integers(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    const char *config_content =
        "listen_port=notanumber\n"
        "cache_capacity=-100\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    proxy_config_t config;
    int result = config_load(&config, temp_file);
    
    assert_int_equal(result, 0);
    /* Should keep defaults for invalid values */
    assert_int_equal(config.listen_port, 53);
    assert_int_equal(config.cache_capacity, 1024);
    
    remove_temp_file(temp_file);
}

/*
 * Test: config_load with NULL config pointer returns error
 */
static void test_config_null_pointer(void **state) {
    (void)state;
    
    int result = config_load(NULL, "/some/path");
    assert_int_equal(result, -1);
}

/*
 * Test: config validation - invalid port
 */
static void test_config_validation_invalid_port(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    const char *config_content = "listen_port=99999\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    proxy_config_t config;
    int result = config_load(&config, temp_file);
    
    /* Port > 65535 should cause validation failure */
    /* Actually, parse_int rejects values > 65535, so it stays at default */
    assert_int_equal(result, 0);
    assert_int_equal(config.listen_port, 53);
    
    remove_temp_file(temp_file);
}

/*
 * Test: DNS_ENCRYPTED_PROXY_CONFIG environment variable for config path
 */
static void test_config_env_config_path(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    const char *config_content = "listen_port=9999\n";
    
    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);
    
    setenv("DNS_ENCRYPTED_PROXY_CONFIG", temp_file, 1);
    
    proxy_config_t config;
    int result = config_load(&config, NULL);
    
    assert_int_equal(result, 0);
    assert_int_equal(config.listen_port, 9999);
    
    remove_temp_file(temp_file);
    clear_config_env_vars();
}

/*
 * Test: config_print outputs correctly
 */
static void test_config_print(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    proxy_config_t config;
    config_load(&config, "/nonexistent/path");
    
    /* Just verify it doesn't crash with NULL output */
    config_print(&config, NULL);
    config_print(NULL, stderr);
    
    /* Verify it works with valid params - output to /dev/null */
    FILE *devnull = fopen("/dev/null", "w");
    if (devnull != NULL) {
        config_print(&config, devnull);
        fclose(devnull);
    }
}

static void test_config_all_env_overrides_and_empty_tokens(void **state) {
    (void)state;

    clear_config_env_vars();

    setenv("LISTEN_ADDR", "127.0.0.9", 1);
    setenv("LISTEN_PORT", "1053", 1);
    setenv("UPSTREAM_TIMEOUT_MS", "4200", 1);
    setenv("UPSTREAM_POOL_SIZE", "11", 1);
    setenv("CACHE_CAPACITY", "333", 1);
    setenv("UPSTREAMS", " ,https://u1.example/dns, , tls://1.1.1.1:853, ", 1);
    setenv("TCP_IDLE_TIMEOUT_MS", "0", 1);
    setenv("TCP_MAX_CLIENTS", "9", 1);
    setenv("TCP_MAX_QUERIES_PER_CONN", "7", 1);
    setenv("METRICS_PORT", "9191", 1);
    setenv("METRICS_ENABLED", "0", 1);

    proxy_config_t config;
    int result = config_load(&config, "/nonexistent/path/config.conf");

    assert_int_equal(result, 0);
    assert_string_equal(config.listen_addr, "127.0.0.9");
    assert_int_equal(config.listen_port, 1053);
    assert_int_equal(config.upstream_timeout_ms, 4200);
    assert_int_equal(config.upstream_pool_size, 11);
    assert_int_equal(config.cache_capacity, 333);
    assert_int_equal(config.upstream_count, 2);
    assert_string_equal(config.upstream_urls[0], "https://u1.example/dns");
    assert_string_equal(config.upstream_urls[1], "tls://1.1.1.1:853");
    assert_int_equal(config.tcp_idle_timeout_ms, 0);
    assert_int_equal(config.tcp_max_clients, 9);
    assert_int_equal(config.tcp_max_queries_per_conn, 7);
    assert_int_equal(config.metrics_port, 9191);
    assert_int_equal(config.metrics_enabled, 0);

    clear_config_env_vars();
}

static void test_config_invalid_lines_and_empty_explicit_path(void **state) {
    (void)state;

    clear_config_env_vars();

    const char *config_content =
        "# missing equals ignored\n"
        "just_text\n"
        "=missing_key\n"
        "missing_value=\n"
        "unknown_key=123\n"
        "listen_port = 5301\n"
        "metrics_enabled = 1\n";

    char *temp_file = create_temp_file(config_content);
    assert_non_null(temp_file);

    setenv("DNS_ENCRYPTED_PROXY_CONFIG", temp_file, 1);

    proxy_config_t config;
    int result = config_load(&config, "");

    assert_int_equal(result, 0);
    assert_string_equal(config.config_path, temp_file);
    assert_int_equal(config.listen_port, 5301);
    assert_int_equal(config.metrics_enabled, 1);

    remove_temp_file(temp_file);
    clear_config_env_vars();
}

static void test_config_validation_failures_from_env(void **state) {
    (void)state;

    clear_config_env_vars();

    proxy_config_t config;

    setenv("UPSTREAMS", "  ,   , ", 1);
    assert_int_equal(config_load(&config, "/nonexistent/path/config.conf"), -1);
    clear_config_env_vars();

    setenv("UPSTREAM_TIMEOUT_MS", "0", 1);
    assert_int_equal(config_load(&config, "/nonexistent/path/config.conf"), -1);
    clear_config_env_vars();

    setenv("UPSTREAM_POOL_SIZE", "0", 1);
    assert_int_equal(config_load(&config, "/nonexistent/path/config.conf"), 0);
    assert_int_equal(config.upstream_pool_size, 6);
    clear_config_env_vars();

    setenv("CACHE_CAPACITY", "0", 1);
    assert_int_equal(config_load(&config, "/nonexistent/path/config.conf"), 0);
    assert_int_equal(config.cache_capacity, 1024);
    clear_config_env_vars();

    setenv("METRICS_PORT", "0", 1);
    assert_int_equal(config_load(&config, "/nonexistent/path/config.conf"), -1);
    clear_config_env_vars();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_defaults),
        cmocka_unit_test(test_config_file_parse),
        cmocka_unit_test(test_config_env_override),
        cmocka_unit_test(test_config_multiple_upstreams),
        cmocka_unit_test(test_config_whitespace_comments),
        cmocka_unit_test(test_config_invalid_integers),
        cmocka_unit_test(test_config_null_pointer),
        cmocka_unit_test(test_config_validation_invalid_port),
        cmocka_unit_test(test_config_env_config_path),
        cmocka_unit_test(test_config_print),
        cmocka_unit_test(test_config_all_env_overrides_and_empty_tokens),
        cmocka_unit_test(test_config_invalid_lines_and_empty_explicit_path),
        cmocka_unit_test(test_config_validation_failures_from_env),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
