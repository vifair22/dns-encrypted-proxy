#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "report.h"
#include "test_report_collector.h"

static void test_format_query_upstream_answer(void **state) {
    (void)state;
    char buf[REPORT_MAX_DATAGRAM];
    report_query_t q = {
        .client = "172.20.8.5",
        .qname = "example.com",
        .qtype = 1,
        .has_qtype = 1,
        .rcode = 0,
        .source = REPORT_SOURCE_UPSTREAM,
        .upstream = "dns.google",
        .proto = "doh",
        .latency_ms = 12.25,
    };
    int n = report_format_query(buf, sizeof(buf), 1795540000.123, &q);
    assert_true(n > 0);
    assert_string_equal(
        buf,
        "{\"type\":\"dns.query\",\"v\":1,\"ts\":1795540000.123,\"client\":\"172.20.8.5\",\"qname\":\"example.com\","
        "\"qtype\":\"A\",\"rcode\":\"NOERROR\",\"upstream\":\"dns.google\",\"proto\":\"doh\","
        "\"source\":\"upstream\",\"latency_ms\":12.250,\"cached\":false}");
    assert_int_equal((size_t)n, strlen(buf));
}

static void test_format_query_cache_hit_has_no_upstream(void **state) {
    (void)state;
    char buf[REPORT_MAX_DATAGRAM];
    report_query_t q = {
        .client = NULL,
        .qname = "",
        .qtype = 2,
        .has_qtype = 1,
        .rcode = 3,
        .source = REPORT_SOURCE_CACHE,
        /* Ignored for anything but an upstream answer. */
        .upstream = "dns.google",
        .proto = "doh",
        .latency_ms = 0.0,
    };
    assert_true(report_format_query(buf, sizeof(buf), 1.0, &q) > 0);
    assert_string_equal(
        buf,
        "{\"type\":\"dns.query\",\"v\":1,\"ts\":1.000,\"client\":null,\"qname\":\".\",\"qtype\":\"NS\","
        "\"rcode\":\"NXDOMAIN\",\"upstream\":null,\"proto\":null,\"source\":\"cache\","
        "\"latency_ms\":0.000,\"cached\":true}");
}

static void test_format_query_sources_and_unknown_question(void **state) {
    (void)state;
    char buf[REPORT_MAX_DATAGRAM];
    report_query_t q = {.qname = NULL, .has_qtype = 0, .rcode = 2, .source = REPORT_SOURCE_FAILURE_CACHE};
    assert_true(report_format_query(buf, sizeof(buf), 1.0, &q) > 0);
    assert_non_null(strstr(buf, "\"qname\":null,\"qtype\":null,\"rcode\":\"SERVFAIL\""));
    assert_non_null(strstr(buf, "\"source\":\"failure_cache\""));
    assert_non_null(strstr(buf, "\"cached\":true"));

    q.source = REPORT_SOURCE_LOCAL;
    assert_true(report_format_query(buf, sizeof(buf), 1.0, &q) > 0);
    assert_non_null(strstr(buf, "\"source\":\"local\""));
    assert_non_null(strstr(buf, "\"cached\":false"));

    q.source = (report_source_t)99;
    assert_true(report_format_query(buf, sizeof(buf), 1.0, &q) > 0);
    assert_non_null(strstr(buf, "\"source\":\"unknown\""));
}

static void test_format_escapes_names(void **state) {
    (void)state;
    char buf[REPORT_MAX_DATAGRAM];
    const char name[] = {'a', '"', 'b', '\\', 'c', '\n', (char)0xC3, (char)0x7F, '\0'};
    report_query_t q = {.qname = name, .qtype = 1, .has_qtype = 1, .source = REPORT_SOURCE_LOCAL};
    assert_true(report_format_query(buf, sizeof(buf), 1.0, &q) > 0);
    assert_non_null(strstr(buf, "\"qname\":\"a\\\"b\\\\c\\u000a\\u00c3\\u007f\""));
}

static void test_format_rejects_what_does_not_fit(void **state) {
    (void)state;
    char small[32];
    report_query_t q = {.qname = "example.com", .qtype = 1, .has_qtype = 1, .source = REPORT_SOURCE_LOCAL};
    assert_int_equal(report_format_query(small, sizeof(small), 1.0, &q), -1);
    assert_int_equal(report_format_upstream(small, sizeof(small), 1.0, "dns.google", "failure", "timeout", "curl=28"), -1);
    assert_int_equal(report_format_query(NULL, 10, 1.0, &q), -1);
    assert_int_equal(report_format_query(small, 0, 1.0, &q), -1);
    assert_int_equal(report_format_query(small, sizeof(small), 1.0, NULL), -1);
    assert_int_equal(report_format_upstream(small, sizeof(small), 1.0, "x", NULL, NULL, NULL), -1);

    /* A name of escaped bytes long enough to overflow mid-escape. */
    char big[1200];
    memset(big, 0x01, sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    char buf[REPORT_MAX_DATAGRAM];
    q.qname = big;
    assert_int_equal(report_format_query(buf, sizeof(buf), 1.0, &q), -1);
}

static void test_format_upstream_event(void **state) {
    (void)state;
    char buf[REPORT_MAX_DATAGRAM];
    assert_true(report_format_upstream(buf, sizeof(buf), 2.5, "dns.google", "failure", "timeout", "curl=28,http=0") > 0);
    assert_string_equal(
        buf,
        "{\"type\":\"dns.upstream\",\"v\":1,\"ts\":2.500,\"upstream\":\"dns.google\",\"event\":\"failure\","
        "\"reason\":\"timeout\",\"detail\":\"curl=28,http=0\"}");
    assert_true(report_format_upstream(buf, sizeof(buf), 2.5, "dns.google", "recovered", NULL, NULL) > 0);
    assert_non_null(strstr(buf, "\"reason\":null,\"detail\":null}"));
}

static void test_type_and_rcode_names(void **state) {
    (void)state;
    char scratch[16];
    const uint16_t known[] = {1, 2, 5, 6, 12, 13, 15, 16, 28, 33, 35, 43, 46, 47, 48, 50, 52, 64, 65, 252, 255, 257};
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        const char *name = report_qtype_name(known[i], scratch, sizeof(scratch));
        assert_true(name != scratch);
        assert_true(strncmp(name, "TYPE", 4) != 0);
    }
    assert_string_equal(report_qtype_name(28, scratch, sizeof(scratch)), "AAAA");
    assert_string_equal(report_qtype_name(65, scratch, sizeof(scratch)), "HTTPS");
    assert_string_equal(report_qtype_name(999, scratch, sizeof(scratch)), "TYPE999");

    for (uint8_t r = 0; r <= 10; r++) {
        assert_true(report_rcode_name(r, scratch, sizeof(scratch)) != scratch);
    }
    assert_string_equal(report_rcode_name(5, scratch, sizeof(scratch)), "REFUSED");
    assert_string_equal(report_rcode_name(10, scratch, sizeof(scratch)), "NOTZONE");
    assert_string_equal(report_rcode_name(12, scratch, sizeof(scratch)), "RCODE12");
}

static void test_open_rejects_bad_paths(void **state) {
    (void)state;
    assert_int_equal(report_open(NULL), PROXY_ERR_INVALID_ARG);
    assert_int_equal(report_open(""), PROXY_ERR_INVALID_ARG);
    char long_path[200];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    assert_int_equal(report_open(long_path), PROXY_ERR_CONFIG);
    assert_false(report_enabled());
}

static void test_disabled_sink_is_a_no_op(void **state) {
    (void)state;
    uint64_t sent = report_sent_total();
    uint64_t dropped = report_dropped_total();
    report_query_t q = {.qname = "example.com", .source = REPORT_SOURCE_LOCAL};
    report_query(&q);
    report_upstream("dns.google", "failure", NULL, NULL);
    assert_int_equal(report_sent_total(), sent);
    assert_int_equal(report_dropped_total(), dropped);
}

static void test_events_reach_the_collector(void **state) {
    (void)state;
    test_collector_t c;
    test_collector_open(&c, 0);
    assert_int_equal(report_open(c.path), PROXY_OK);
    assert_true(report_enabled());
    assert_int_equal(report_open(c.path), PROXY_ERR_INTERNAL);

    uint64_t sent = report_sent_total();
    report_query_t q = {
        .client = "10.0.0.2", .qname = "example.com", .qtype = 28, .has_qtype = 1,
        .rcode = 0, .source = REPORT_SOURCE_UPSTREAM, .upstream = "dns.google", .proto = "dot",
        .latency_ms = 3.0,
    };
    report_query(&q);
    report_upstream("dns.google", "redial", "unanswered", NULL);
    report_query(NULL);
    report_upstream("dns.google", NULL, NULL, NULL);

    char buf[REPORT_MAX_DATAGRAM];
    assert_true(test_collector_recv(&c, buf, sizeof(buf), 1000) > 0);
    assert_non_null(strstr(buf, "\"type\":\"dns.query\",\"v\":1,"));
    assert_non_null(strstr(buf, "\"client\":\"10.0.0.2\""));
    assert_non_null(strstr(buf, "\"qtype\":\"AAAA\""));
    assert_non_null(strstr(buf, "\"proto\":\"dot\""));
    assert_true(test_collector_recv(&c, buf, sizeof(buf), 1000) > 0);
    assert_non_null(strstr(buf, "\"event\":\"redial\",\"reason\":\"unanswered\""));
    assert_int_equal(report_sent_total(), sent + 2);

    report_close();
    assert_false(report_enabled());
    report_close();
    test_collector_close(&c);
}

static void test_absent_or_full_collector_drops_without_blocking(void **state) {
    (void)state;
    test_collector_t c;
    test_collector_open(&c, 0);
    int small = 4096;
    assert_int_equal(setsockopt(c.fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)), 0);
    assert_int_equal(report_open(c.path), PROXY_OK);

    /* Nobody reads: the receive queue fills and further events must be
     * dropped, not wait. The loop finishing at all is the non-blocking proof. */
    uint64_t dropped = report_dropped_total();
    for (int i = 0; i < 2000; i++) {
        report_upstream("dns.google", "failure", "timeout", "curl=28,http=0,sent=1");
    }
    assert_true(report_dropped_total() > dropped);

    /* Collector gone entirely, with the proxy's sink still open. */
    close(c.fd);
    c.fd = -1;
    unlink(c.path);
    dropped = report_dropped_total();
    report_upstream("dns.google", "failure", NULL, NULL);
    assert_int_equal(report_dropped_total(), dropped + 1);

    /* An event too large for one datagram is dropped, not truncated. */
    char big[REPORT_MAX_DATAGRAM];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    dropped = report_dropped_total();
    report_upstream("dns.google", "failure", NULL, big);
    assert_int_equal(report_dropped_total(), dropped + 1);

    test_collector_close(&c);
}

static void *note_on_other_thread(void *arg) {
    (void)arg;
    report_note_attempt_failure("tls_handshake_failed", "other thread");
    return NULL;
}

static void test_failure_note_is_per_thread_and_taken_once(void **state) {
    (void)state;
    char reason[48];
    char detail[96];

    report_note_attempt_failure("timeout", "curl=28,http=0,sent=1");
    pthread_t t;
    assert_int_equal(pthread_create(&t, NULL, note_on_other_thread, NULL), 0);
    pthread_join(t, NULL);

    report_take_attempt_failure(reason, sizeof(reason), detail, sizeof(detail));
    assert_string_equal(reason, "timeout");
    assert_string_equal(detail, "curl=28,http=0,sent=1");

    report_take_attempt_failure(reason, sizeof(reason), detail, sizeof(detail));
    assert_string_equal(reason, "");
    assert_string_equal(detail, "");

    report_note_attempt_failure(NULL, NULL);
    report_take_attempt_failure(NULL, 0, NULL, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_format_query_upstream_answer),
        cmocka_unit_test(test_format_query_cache_hit_has_no_upstream),
        cmocka_unit_test(test_format_query_sources_and_unknown_question),
        cmocka_unit_test(test_format_escapes_names),
        cmocka_unit_test(test_format_rejects_what_does_not_fit),
        cmocka_unit_test(test_format_upstream_event),
        cmocka_unit_test(test_type_and_rcode_names),
        cmocka_unit_test(test_open_rejects_bad_paths),
        cmocka_unit_test(test_disabled_sink_is_a_no_op),
        cmocka_unit_test(test_events_reach_the_collector),
        cmocka_unit_test(test_absent_or_full_collector_drops_without_blocking),
        cmocka_unit_test(test_failure_note_is_per_thread_and_taken_once),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
