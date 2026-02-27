#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>

#undef UPSTREAM_DOQ_NGTCP2_ENABLED
#define UPSTREAM_DOQ_NGTCP2_ENABLED 1
#include "../../src/upstream_doq_ngtcp2.c"

static void test_prepare_query_stream_data_success(void **state) {
    (void)state;

    uint8_t query[] = {0x12, 0x34, 0x56};
    uint8_t out[16] = {0};
    size_t out_len = 0;

    assert_int_equal(doq_prepare_query_stream_data(query, sizeof(query), out, &out_len), 0);
    assert_int_equal((int)out_len, 5);
    assert_int_equal(out[0], 0x00);
    assert_int_equal(out[1], 0x03);
    assert_memory_equal(out + 2, query, sizeof(query));
}

static void test_prepare_query_stream_data_guards(void **state) {
    (void)state;

    uint8_t query[] = {0x01};
    uint8_t out[4] = {0};
    size_t out_len = 0;

    assert_int_equal(doq_prepare_query_stream_data(NULL, sizeof(query), out, &out_len), -1);
    assert_int_equal(doq_prepare_query_stream_data(query, 0, out, &out_len), -1);
    assert_int_equal(doq_prepare_query_stream_data(query, sizeof(query), NULL, &out_len), -1);
    assert_int_equal(doq_prepare_query_stream_data(query, sizeof(query), out, NULL), -1);
    assert_int_equal(doq_prepare_query_stream_data(query, DOQ_MAX_DNS_MESSAGE_SIZE + 1, out, &out_len), -1);
}

static void test_recv_stream_data_complete_frame(void **state) {
    (void)state;

    doq_ngtcp2_session_t session;
    memset(&session, 0, sizeof(session));
    session.stream_id = 4;

    uint8_t chunk1[] = {0x00, 0x03, 0xaa};
    uint8_t chunk2[] = {0xbb, 0xcc};

    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 4, 0, chunk1, sizeof(chunk1), &session, NULL),
        0);
    assert_int_equal(session.stream_expected_len, 5);
    assert_int_equal(session.stream_response_ready, 0);

    assert_int_equal(
        doq_ngtcp2_recv_stream_data(
            NULL,
            NGTCP2_STREAM_DATA_FLAG_FIN,
            4,
            sizeof(chunk1),
            chunk2,
            sizeof(chunk2),
            &session,
            NULL),
        0);
    assert_int_equal(session.stream_rx_len, 5);
    assert_int_equal(session.stream_fin, 1);
    assert_int_equal(session.stream_response_ready, 1);
}

static void test_recv_stream_data_offset_and_bounds_guards(void **state) {
    (void)state;

    doq_ngtcp2_session_t session;
    memset(&session, 0, sizeof(session));
    session.stream_id = 0;
    session.stream_rx_len = 2;

    uint8_t data[] = {0x11};

    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 0, 1, data, sizeof(data), &session, NULL),
        NGTCP2_ERR_CALLBACK_FAILURE);

    session.stream_rx_len = sizeof(session.stream_rx) - 1;
    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 0, session.stream_rx_len, data, sizeof(data) + 1, &session, NULL),
        NGTCP2_ERR_CALLBACK_FAILURE);
}

static void test_recv_stream_data_null_session_fails(void **state) {
    (void)state;
    uint8_t data[] = {0x00};
    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 0, 0, data, sizeof(data), NULL, NULL),
        NGTCP2_ERR_CALLBACK_FAILURE);
}

static void test_recv_stream_data_max_announced_length_accepted(void **state) {
    (void)state;

    doq_ngtcp2_session_t session;
    memset(&session, 0, sizeof(session));
    session.stream_id = 2;

    uint8_t header[] = {0xFF, 0xFF};
    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 2, 0, header, sizeof(header), &session, NULL),
        0);
    assert_int_equal(session.stream_expected_len, sizeof(session.stream_rx));
}

static void test_recv_stream_data_more_than_announced_guard(void **state) {
    (void)state;

    doq_ngtcp2_session_t session;
    memset(&session, 0, sizeof(session));
    session.stream_id = 7;

    uint8_t header_and_payload[] = {0x00, 0x01, 0xAA};
    uint8_t extra = 0xBB;
    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 7, 0, header_and_payload, sizeof(header_and_payload), &session, NULL),
        0);
    assert_int_equal(session.stream_expected_len, 3);

    assert_int_equal(
        doq_ngtcp2_recv_stream_data(NULL, 0, 7, 3, &extra, 1, &session, NULL),
        NGTCP2_ERR_CALLBACK_FAILURE);
}

static void test_recv_stream_data_ignores_other_stream_id(void **state) {
    (void)state;

    doq_ngtcp2_session_t session;
    memset(&session, 0, sizeof(session));
    session.stream_id = 4;

    uint8_t data[] = {0x00, 0x01, 0xaa};
    assert_int_equal(doq_ngtcp2_recv_stream_data(NULL, 0, 8, 0, data, sizeof(data), &session, NULL), 0);
    assert_int_equal(session.stream_rx_len, 0);
    assert_int_equal(session.stream_expected_len, 0);
}

static int reserve_unused_udp_port(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }

    int port = (int)ntohs(addr.sin_port);
    close(fd);
    return port;
}

static void test_resolve_timeout_path_no_server(void **state) {
    (void)state;

    int port = reserve_unused_udp_port();
    assert_true(port > 0);

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    strcpy(server.host, "127.0.0.1");
    server.port = port;

    uint8_t query[] = {0x12, 0x34, 0x01, 0x00};
    uint8_t *response = (uint8_t *)(uintptr_t)0x1;
    size_t response_len = 123;

    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 20, query, sizeof(query), &response, &response_len), -1);
    assert_null(response);
    assert_int_equal(response_len, 0);
}

static void test_wait_for_io_invalid_fd(void **state) {
    (void)state;
    assert_int_equal(doq_ngtcp2_wait_for_io(-1, now_ns() + 1000000ULL), -1);
}

static void test_wait_for_io_timeout_returns_zero(void **state) {
    (void)state;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert_true(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert_int_equal(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

    uint64_t deadline = now_ns() + 2 * 1000000ULL;
    int rc = doq_ngtcp2_wait_for_io(fd, deadline);
    assert_true(rc == 0 || rc == 1);

    close(fd);
}

static void test_resolve_argument_guards(void **state) {
    (void)state;

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    strcpy(server.host, "127.0.0.1");
    server.port = 853;

    uint8_t query[] = {0x12, 0x34};
    uint8_t *response = NULL;
    size_t response_len = 0;

    assert_int_equal(upstream_doq_ngtcp2_resolve(NULL, 100, query, sizeof(query), &response, &response_len), -1);
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, NULL, sizeof(query), &response, &response_len), -1);
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, query, 0, &response, &response_len), -1);
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, query, sizeof(query), NULL, &response_len), -1);
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, query, sizeof(query), &response, NULL), -1);

    server.host[0] = '\0';
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, query, sizeof(query), &response, &response_len), -1);

    strcpy(server.host, "127.0.0.1");
    server.port = 0;
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, query, sizeof(query), &response, &response_len), -1);

    server.port = 70000;
    assert_int_equal(upstream_doq_ngtcp2_resolve(&server, 100, query, sizeof(query), &response, &response_len), -1);

    uint8_t *oversized = malloc(DOQ_MAX_DNS_MESSAGE_SIZE + 1);
    assert_non_null(oversized);
    memset(oversized, 0xAB, DOQ_MAX_DNS_MESSAGE_SIZE + 1);
    server.port = 853;
    assert_int_equal(
        upstream_doq_ngtcp2_resolve(
            &server,
            100,
            oversized,
            DOQ_MAX_DNS_MESSAGE_SIZE + 1,
            &response,
            &response_len),
        -1);
    free(oversized);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_prepare_query_stream_data_success),
        cmocka_unit_test(test_prepare_query_stream_data_guards),
        cmocka_unit_test(test_recv_stream_data_complete_frame),
        cmocka_unit_test(test_recv_stream_data_offset_and_bounds_guards),
        cmocka_unit_test(test_recv_stream_data_null_session_fails),
        cmocka_unit_test(test_recv_stream_data_max_announced_length_accepted),
        cmocka_unit_test(test_recv_stream_data_more_than_announced_guard),
        cmocka_unit_test(test_recv_stream_data_ignores_other_stream_id),
        cmocka_unit_test(test_wait_for_io_invalid_fd),
        cmocka_unit_test(test_wait_for_io_timeout_returns_zero),
        cmocka_unit_test(test_resolve_timeout_path_no_server),
        cmocka_unit_test(test_resolve_argument_guards),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
