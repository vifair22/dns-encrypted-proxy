#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "upstream.h"

static int g_backend_rc = -1;
static uint8_t *g_backend_resp = NULL;
static size_t g_backend_resp_len = 0;
static int g_validate_rc = 0;

static void reset_stubs(void) {
    g_backend_rc = -1;
    g_backend_resp = NULL;
    g_backend_resp_len = 0;
    g_validate_rc = 0;
}

int upstream_doq_ngtcp2_resolve(
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)server;
    (void)timeout_ms;
    (void)query;
    (void)query_len;

    if (response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    if (g_backend_rc != 0) {
        *response_out = NULL;
        *response_len_out = 0;
        return -1;
    }

    if (g_backend_resp_len == 0 || g_backend_resp == NULL) {
        *response_out = NULL;
        *response_len_out = 0;
        return 0;
    }

    uint8_t *copy = malloc(g_backend_resp_len);
    assert_non_null(copy);
    memcpy(copy, g_backend_resp, g_backend_resp_len);
    *response_out = copy;
    *response_len_out = g_backend_resp_len;
    return 0;
}

int dns_validate_response_for_query(
    const uint8_t *query,
    size_t query_len,
    const uint8_t *response,
    size_t response_len) {
    (void)query;
    (void)query_len;
    (void)response;
    (void)response_len;
    return g_validate_rc;
}

#undef UPSTREAM_DOQ_NGTCP2_ENABLED
#define UPSTREAM_DOQ_NGTCP2_ENABLED 1
#include "../../src/upstream_doq.c"

static void test_upstream_doq_resolve_backend_failure(void **state) {
    (void)state;
    reset_stubs();

    upstream_doq_client_t client = {.pool_size = 1, .ngtcp2_enabled = 1};
    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOQ;

    uint8_t query[] = {0x12, 0x34};
    uint8_t *response = (uint8_t *)(uintptr_t)0x1;
    size_t response_len = 999;

    assert_int_equal(
        upstream_doq_resolve(&client, &server, 100, query, sizeof(query), &response, &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);
}

static void test_upstream_doq_resolve_validation_failure_frees_response(void **state) {
    (void)state;
    reset_stubs();

    upstream_doq_client_t client = {.pool_size = 1, .ngtcp2_enabled = 1};
    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOQ;

    uint8_t backend_resp[] = {0x12, 0x34, 0x81, 0x80};
    g_backend_rc = 0;
    g_backend_resp = backend_resp;
    g_backend_resp_len = sizeof(backend_resp);
    g_validate_rc = -1;

    uint8_t query[] = {0x12, 0x34};
    uint8_t *response = NULL;
    size_t response_len = 0;

    assert_int_equal(
        upstream_doq_resolve(&client, &server, 100, query, sizeof(query), &response, &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);
}

static void test_upstream_doq_resolve_success_path(void **state) {
    (void)state;
    reset_stubs();

    upstream_doq_client_t client = {.pool_size = 2, .ngtcp2_enabled = 1};
    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOQ;

    uint8_t backend_resp[] = {0x12, 0x34, 0x81, 0x80};
    g_backend_rc = 0;
    g_backend_resp = backend_resp;
    g_backend_resp_len = sizeof(backend_resp);
    g_validate_rc = 0;

    uint8_t query[] = {0x12, 0x34};
    uint8_t *response = NULL;
    size_t response_len = 0;

    assert_int_equal(
        upstream_doq_resolve(&client, &server, 100, query, sizeof(query), &response, &response_len),
        0);
    assert_non_null(response);
    assert_int_equal((int)response_len, (int)sizeof(backend_resp));
    assert_memory_equal(response, backend_resp, sizeof(backend_resp));
    free(response);
}

static void test_upstream_doq_resolve_guards(void **state) {
    (void)state;
    reset_stubs();

    upstream_doq_client_t client = {.pool_size = 1, .ngtcp2_enabled = 1};
    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOQ;

    uint8_t query[] = {0x12, 0x34};
    uint8_t *response = NULL;
    size_t response_len = 0;

    assert_int_equal(upstream_doq_resolve(NULL, &server, 100, query, sizeof(query), &response, &response_len), -1);
    assert_int_equal(upstream_doq_resolve(&client, NULL, 100, query, sizeof(query), &response, &response_len), -1);
    assert_int_equal(upstream_doq_resolve(&client, &server, 100, NULL, sizeof(query), &response, &response_len), -1);
    assert_int_equal(upstream_doq_resolve(&client, &server, 100, query, 0, &response, &response_len), -1);
    assert_int_equal(upstream_doq_resolve(&client, &server, 100, query, sizeof(query), NULL, &response_len), -1);
    assert_int_equal(upstream_doq_resolve(&client, &server, 100, query, sizeof(query), &response, NULL), -1);

    server.type = UPSTREAM_TYPE_DOH;
    assert_int_equal(upstream_doq_resolve(&client, &server, 100, query, sizeof(query), &response, &response_len), -1);

    uint8_t *oversized = malloc(65536);
    assert_non_null(oversized);
    memset(oversized, 0xAB, 65536);
    server.type = UPSTREAM_TYPE_DOQ;
    assert_int_equal(upstream_doq_resolve(&client, &server, 100, oversized, 65536, &response, &response_len), -1);
    free(oversized);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_upstream_doq_resolve_backend_failure),
        cmocka_unit_test(test_upstream_doq_resolve_validation_failure_frees_response),
        cmocka_unit_test(test_upstream_doq_resolve_success_path),
        cmocka_unit_test(test_upstream_doq_resolve_guards),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
