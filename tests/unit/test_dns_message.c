/*
 * Unit tests for dns_message.c
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "dns_message.h"
#include "test_helpers.h"
#include "test_fixtures.h"

/*
 * Test: dns_extract_question_key with standard query
 */
static void test_extract_question_key_basic(void **state) {
    (void)state;
    
    uint8_t key[512];
    size_t key_len = 0;
    
    int result = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key, sizeof(key), &key_len);
    
    assert_int_equal(result, 0);
    assert_true(key_len > 0);
    assert_true(key_len < sizeof(key));
}

/*
 * Test: dns_extract_question_key with EDNS query
 */
static void test_extract_question_key_edns(void **state) {
    (void)state;
    
    uint8_t key[512];
    size_t key_len = 0;
    
    int result = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
        key, sizeof(key), &key_len);
    
    assert_int_equal(result, 0);
    assert_true(key_len > 0);
}

/*
 * Test: dns_extract_question_key with EDNS and DO bit
 */
static void test_extract_question_key_edns_do(void **state) {
    (void)state;
    
    uint8_t key_plain[512];
    uint8_t key_do[512];
    size_t key_plain_len = 0;
    size_t key_do_len = 0;
    
    int result1 = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
        key_plain, sizeof(key_plain), &key_plain_len);
    
    int result2 = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_DO,
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_DO_LEN,
        key_do, sizeof(key_do), &key_do_len);
    
    assert_int_equal(result1, 0);
    assert_int_equal(result2, 0);
    
    /* Keys should be different because DO bit affects caching */
    assert_true(key_plain_len != key_do_len || memcmp(key_plain, key_do, key_plain_len) != 0);
}

/*
 * Test: dns_extract_question_key is case-insensitive
 */
static void test_extract_question_key_case_insensitive(void **state) {
    (void)state;
    
    uint8_t key_lower[512];
    uint8_t key_upper[512];
    size_t key_lower_len = 0;
    size_t key_upper_len = 0;
    
    int result1 = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key_lower, sizeof(key_lower), &key_lower_len);
    
    int result2 = dns_extract_question_key(
        DNS_QUERY_UPPERCASE,
        DNS_QUERY_UPPERCASE_LEN,
        key_upper, sizeof(key_upper), &key_upper_len);
    
    assert_int_equal(result1, 0);
    assert_int_equal(result2, 0);
    
    /* Keys should be identical despite case difference in domain */
    assert_int_equal(key_lower_len, key_upper_len);
    assert_memory_equal(key_lower, key_upper, key_lower_len);
}

/*
 * Test: dns_extract_question_key with invalid input
 */
static void test_extract_question_key_invalid(void **state) {
    (void)state;
    
    uint8_t key[512];
    size_t key_len = 0;
    
    /* NULL query */
    int result = dns_extract_question_key(NULL, 10, key, sizeof(key), &key_len);
    assert_int_equal(result, -1);
    
    /* NULL key_out */
    result = dns_extract_question_key(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, NULL, 512, &key_len);
    assert_int_equal(result, -1);
    
    /* NULL key_len_out */
    result = dns_extract_question_key(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, key, sizeof(key), NULL);
    assert_int_equal(result, -1);
    
    /* Too short message (less than header) */
    result = dns_extract_question_key(DNS_MALFORMED_SHORT_HEADER, DNS_MALFORMED_SHORT_HEADER_LEN, key, sizeof(key), &key_len);
    assert_int_equal(result, -1);
}

/*
 * Test: dns_extract_question_key with malformed packet
 */
static void test_extract_question_key_malformed(void **state) {
    (void)state;
    
    uint8_t key[512];
    size_t key_len = 0;
    
    int result = dns_extract_question_key(
        DNS_MALFORMED_BAD_LABEL,
        DNS_MALFORMED_BAD_LABEL_LEN,
        key, sizeof(key), &key_len);
    
    assert_int_equal(result, -1);
}

/*
 * Test: dns_question_section_length
 */
static void test_question_section_length(void **state) {
    (void)state;
    
    size_t section_len = 0;
    
    int result = dns_question_section_length(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        &section_len);
    
    assert_int_equal(result, 0);
    /* www.example.com = 3+www+7+example+3+com+0 + QTYPE(2) + QCLASS(2) = 21 bytes */
    assert_int_equal(section_len, 21);
}

/*
 * Test: dns_question_section_length with invalid input
 */
static void test_question_section_length_invalid(void **state) {
    (void)state;
    
    size_t section_len = 0;
    
    /* NULL message */
    int result = dns_question_section_length(NULL, 10, &section_len);
    assert_int_equal(result, -1);
    
    /* NULL output */
    result = dns_question_section_length(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, NULL);
    assert_int_equal(result, -1);
    
    /* Too short */
    result = dns_question_section_length(DNS_MALFORMED_SHORT_HEADER, DNS_MALFORMED_SHORT_HEADER_LEN, &section_len);
    assert_int_equal(result, -1);
}

/*
 * Test: dns_udp_payload_limit_for_query without EDNS
 */
static void test_udp_payload_limit_no_edns(void **state) {
    (void)state;
    
    size_t limit = dns_udp_payload_limit_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    
    /* Without EDNS, should return legacy 512 */
    assert_int_equal(limit, 512);
}

/*
 * Test: dns_udp_payload_limit_for_query with EDNS
 */
static void test_udp_payload_limit_with_edns(void **state) {
    (void)state;
    
    size_t limit = dns_udp_payload_limit_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN);
    
    /* With EDNS advertising 4096, should return 4096 (capped) */
    assert_int_equal(limit, 4096);
}

/*
 * Test: dns_udp_payload_limit_for_query with invalid input
 */
static void test_udp_payload_limit_invalid(void **state) {
    (void)state;
    
    /* NULL query */
    size_t limit = dns_udp_payload_limit_for_query(NULL, 100);
    assert_int_equal(limit, 512);
    
    /* Too short */
    limit = dns_udp_payload_limit_for_query(DNS_MALFORMED_SHORT_HEADER, DNS_MALFORMED_SHORT_HEADER_LEN);
    assert_int_equal(limit, 512);
}

/*
 * Test: dns_response_min_ttl extracts minimum TTL
 */
static void test_response_min_ttl_single(void **state) {
    (void)state;
    
    int ok = 0;
    uint32_t min_ttl = dns_response_min_ttl(
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN,
        &ok);
    
    assert_int_equal(ok, 1);
    assert_int_equal(min_ttl, 300);  /* TTL in fixture is 300 */
}

/*
 * Test: dns_response_min_ttl with multiple answers
 */
static void test_response_min_ttl_multiple(void **state) {
    (void)state;
    
    int ok = 0;
    uint32_t min_ttl = dns_response_min_ttl(
        DNS_RESPONSE_MULTI_ANSWER,
        DNS_RESPONSE_MULTI_ANSWER_LEN,
        &ok);
    
    assert_int_equal(ok, 1);
    assert_int_equal(min_ttl, 100);  /* Minimum of 300, 100, 600 */
}

/*
 * Test: dns_response_min_ttl with NXDOMAIN (negative caching)
 */
static void test_response_min_ttl_nxdomain(void **state) {
    (void)state;
    
    int ok = 0;
    uint32_t min_ttl = dns_response_min_ttl(
        DNS_RESPONSE_NXDOMAIN,
        DNS_RESPONSE_NXDOMAIN_LEN,
        &ok);
    
    assert_int_equal(ok, 1);
    /* Should use SOA minimum (60) from the authority section */
    assert_int_equal(min_ttl, 60);
}

/*
 * Test: dns_adjust_response_ttls ages TTLs correctly
 */
static void test_adjust_response_ttls(void **state) {
    (void)state;
    
    /* Make a copy of the response to modify */
    uint8_t response[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(response, DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    
    /* Get original TTL */
    int ok = 0;
    uint32_t original_ttl = dns_response_min_ttl(response, sizeof(response), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(original_ttl, 300);
    
    /* Age by 100 seconds */
    int result = dns_adjust_response_ttls(response, sizeof(response), 100);
    assert_int_equal(result, 0);
    
    /* Check new TTL */
    uint32_t new_ttl = dns_response_min_ttl(response, sizeof(response), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(new_ttl, 200);  /* 300 - 100 = 200 */
}

/*
 * Test: dns_adjust_response_ttls clamps at zero
 */
static void test_adjust_response_ttls_clamp(void **state) {
    (void)state;
    
    uint8_t response[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(response, DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    
    /* Age by more than the TTL */
    int result = dns_adjust_response_ttls(response, sizeof(response), 500);
    assert_int_equal(result, 0);
    
    /* Check TTL is clamped to 0 */
    int ok = 0;
    uint32_t new_ttl = dns_response_min_ttl(response, sizeof(response), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(new_ttl, 0);
}

/*
 * Test: dns_response_is_cacheable
 */
static void test_response_is_cacheable_valid(void **state) {
    (void)state;
    
    /* Normal response is cacheable */
    int cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(cacheable, 1);
    
    /* NXDOMAIN is cacheable */
    cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_NXDOMAIN,
        DNS_RESPONSE_NXDOMAIN_LEN);
    assert_int_equal(cacheable, 1);
}

/*
 * Test: dns_response_is_cacheable rejects truncated
 */
static void test_response_is_cacheable_truncated(void **state) {
    (void)state;
    
    int cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_TRUNCATED,
        DNS_RESPONSE_TRUNCATED_LEN);
    
    /* TC bit set - should not be cached */
    assert_int_equal(cacheable, 0);
}

/*
 * Test: dns_response_is_cacheable rejects SERVFAIL
 */
static void test_response_is_cacheable_servfail(void **state) {
    (void)state;
    
    int cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_SERVFAIL,
        DNS_RESPONSE_SERVFAIL_LEN);
    
    /* RCODE=2 (SERVFAIL) - should not be cached */
    assert_int_equal(cacheable, 0);
}

/*
 * Test: dns_validate_response_for_query with matching query/response
 */
static void test_validate_response_matching(void **state) {
    (void)state;
    
    int result = dns_validate_response_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    
    assert_int_equal(result, 0);
}

/*
 * Test: dns_validate_response_for_query rejects mismatched
 */
static void test_validate_response_mismatched(void **state) {
    (void)state;
    
    /* Query for www.example.com A but response is NXDOMAIN for different domain */
    int result = dns_validate_response_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        DNS_RESPONSE_NXDOMAIN,
        DNS_RESPONSE_NXDOMAIN_LEN);
    
    /* Question sections don't match */
    assert_int_equal(result, -1);
}

/*
 * Test: dns_validate_response_for_query with invalid input
 */
static void test_validate_response_invalid(void **state) {
    (void)state;
    
    /* NULL query */
    int result = dns_validate_response_for_query(
        NULL, 10,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(result, -1);
    
    /* NULL response */
    result = dns_validate_response_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        NULL, 10);
    assert_int_equal(result, -1);
    
    /* Too short query */
    result = dns_validate_response_for_query(
        DNS_MALFORMED_SHORT_HEADER, DNS_MALFORMED_SHORT_HEADER_LEN,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(result, -1);
}

/*
 * Test: different query types produce different cache keys
 */
static void test_different_qtypes_different_keys(void **state) {
    (void)state;
    
    uint8_t key_a[512];
    uint8_t key_aaaa[512];
    size_t key_a_len = 0;
    size_t key_aaaa_len = 0;
    
    int result1 = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key_a, sizeof(key_a), &key_a_len);
    
    int result2 = dns_extract_question_key(
        DNS_QUERY_EXAMPLE_COM_AAAA,
        DNS_QUERY_EXAMPLE_COM_AAAA_LEN,
        key_aaaa, sizeof(key_aaaa), &key_aaaa_len);
    
    assert_int_equal(result1, 0);
    assert_int_equal(result2, 0);
    
    /* Keys should be different due to different QTYPE and QNAME */
    assert_true(key_a_len != key_aaaa_len || memcmp(key_a, key_aaaa, key_a_len) != 0);
}


/*
 * EDNS Client Subnet handling. ecs_query builds www.example.com A with an
 * OPT record holding `options` verbatim.
 */
static size_t ecs_query(uint8_t *out, size_t cap, const uint8_t *options, size_t options_len) {
    size_t len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    assert_true(len + 11 + options_len <= cap);
    memcpy(out, DNS_QUERY_WWW_EXAMPLE_COM_A, len);
    out[10] = 0;
    out[11] = 1; /* ARCOUNT */
    const uint8_t opt_header[] = {0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(out + len, opt_header, sizeof(opt_header));
    len += sizeof(opt_header);
    out[len++] = (uint8_t)(options_len >> 8);
    out[len++] = (uint8_t)(options_len & 0xFF);
    memcpy(out + len, options, options_len);
    return len + options_len;
}

static void test_client_subnet_v4_is_reported_and_removed(void **state) {
    (void)state;
    const uint8_t ecs[] = {0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 32, 0, 192, 168, 1, 50};
    uint8_t query[128];
    size_t len = ecs_query(query, sizeof(query), ecs, sizeof(ecs));
    uint8_t expected[128];
    size_t expected_len = ecs_query(expected, sizeof(expected), NULL, 0);

    char addr[64];
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 1);
    assert_string_equal(addr, "192.168.1.50");
    assert_int_equal(len, expected_len);
    assert_memory_equal(query, expected, expected_len);

    /* Stripped, the query keys the same as one that never carried ECS. */
    uint8_t key_a[512];
    uint8_t key_b[512];
    size_t key_a_len = 0;
    size_t key_b_len = 0;
    assert_int_equal(dns_extract_question_key(query, len, key_a, sizeof(key_a), &key_a_len), 0);
    assert_int_equal(dns_extract_question_key(expected, expected_len, key_b, sizeof(key_b), &key_b_len), 0);
    assert_int_equal(key_a_len, key_b_len);
    assert_memory_equal(key_a, key_b, key_a_len);

    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 0);
    assert_string_equal(addr, "");
}

static void test_client_subnet_v6_prefix_is_zero_padded(void **state) {
    (void)state;
    /* /56 carries seven address bytes. */
    const uint8_t ecs[] = {0x00, 0x08, 0x00, 0x0B, 0x00, 0x02, 56, 0, 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56};
    uint8_t query[128];
    size_t len = ecs_query(query, sizeof(query), ecs, sizeof(ecs));
    char addr[64];
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 1);
    assert_string_equal(addr, "2001:db8:1234:5600::");
}

static void test_client_subnet_among_other_options(void **state) {
    (void)state;
    const uint8_t options[] = {
        0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8,       /* COOKIE */
        0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 24, 0, 10, 1, 2,  /* ECS /24 */
        0x00, 0x0C, 0x00, 0x02, 0, 0,                         /* PADDING */
    };
    const uint8_t remaining[] = {
        0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8,
        0x00, 0x0C, 0x00, 0x02, 0, 0,
    };
    uint8_t query[160];
    size_t len = ecs_query(query, sizeof(query), options, sizeof(options));
    uint8_t expected[160];
    size_t expected_len = ecs_query(expected, sizeof(expected), remaining, sizeof(remaining));

    char addr[64];
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 1);
    assert_string_equal(addr, "10.1.2.0");
    assert_int_equal(len, expected_len);
    assert_memory_equal(query, expected, expected_len);
}

static void test_client_subnet_malformed_option_is_still_removed(void **state) {
    (void)state;
    const uint8_t bad_family[] = {0x00, 0x08, 0x00, 0x05, 0x00, 0x09, 8, 0, 10};
    const uint8_t prefix_mismatch[] = {0x00, 0x08, 0x00, 0x05, 0x00, 0x01, 32, 0, 10};
    const uint8_t too_short[] = {0x00, 0x08, 0x00, 0x02, 0x00, 0x01};
    const uint8_t prefix_too_long[] = {0x00, 0x08, 0x00, 0x09, 0x00, 0x01, 40, 0, 1, 2, 3, 4, 5};
    const uint8_t *cases[] = {bad_family, prefix_mismatch, too_short, prefix_too_long};
    const size_t lens[] = {sizeof(bad_family), sizeof(prefix_mismatch), sizeof(too_short), sizeof(prefix_too_long)};
    uint8_t expected[128];
    size_t expected_len = ecs_query(expected, sizeof(expected), NULL, 0);

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t query[128];
        size_t len = ecs_query(query, sizeof(query), cases[i], lens[i]);
        char addr[64] = "stale";
        assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 1);
        assert_string_equal(addr, "");
        assert_int_equal(len, expected_len);
    }

    /* Without an output buffer the option is removed all the same. */
    uint8_t query[128];
    size_t len = ecs_query(query, sizeof(query), bad_family, sizeof(bad_family));
    assert_int_equal(dns_query_take_client_subnet(query, &len, NULL, 0), 1);
    const uint8_t good[] = {0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 32, 0, 192, 168, 1, 50};
    len = ecs_query(query, sizeof(query), good, sizeof(good));
    assert_int_equal(dns_query_take_client_subnet(query, &len, NULL, 0), 1);
    assert_int_equal(len, expected_len);
}

static void test_client_subnet_absent_or_malformed_query(void **state) {
    (void)state;
    char addr[64];
    uint8_t query[128];

    /* No OPT at all. */
    memcpy(query, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    size_t len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 0);
    assert_int_equal(len, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);

    /* OPT with a cookie only. */
    const uint8_t cookie[] = {0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8};
    len = ecs_query(query, sizeof(query), cookie, sizeof(cookie));
    size_t before = len;
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 0);
    assert_int_equal(len, before);

    /* Option length runs past the OPT record. */
    const uint8_t overrun[] = {0x00, 0x08, 0x00, 0x40, 0x00, 0x01};
    len = ecs_query(query, sizeof(query), overrun, sizeof(overrun));
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), -1);

    /* A trailing partial option header. */
    const uint8_t partial[] = {0x00, 0x08, 0x00};
    len = ecs_query(query, sizeof(query), partial, sizeof(partial));
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), -1);

    /* OPT rdlength past the end of the message. */
    len = ecs_query(query, sizeof(query), cookie, sizeof(cookie));
    len -= 4;
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), -1);

    /* Truncated question and missing arguments. */
    len = 14;
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), -1);
    len = 4;
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), -1);
    assert_int_equal(dns_query_take_client_subnet(NULL, &len, addr, sizeof(addr)), -1);
    assert_int_equal(dns_query_take_client_subnet(query, NULL, addr, sizeof(addr)), -1);

    /* An OPT-typed record in the answer section is not the query's OPT. */
    len = ecs_query(query, sizeof(query), cookie, sizeof(cookie));
    query[7] = 1;  /* ANCOUNT */
    query[11] = 0; /* ARCOUNT */
    assert_int_equal(dns_query_take_client_subnet(query, &len, addr, sizeof(addr)), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_extract_question_key_basic),
        cmocka_unit_test(test_extract_question_key_edns),
        cmocka_unit_test(test_extract_question_key_edns_do),
        cmocka_unit_test(test_extract_question_key_case_insensitive),
        cmocka_unit_test(test_extract_question_key_invalid),
        cmocka_unit_test(test_extract_question_key_malformed),
        cmocka_unit_test(test_question_section_length),
        cmocka_unit_test(test_question_section_length_invalid),
        cmocka_unit_test(test_udp_payload_limit_no_edns),
        cmocka_unit_test(test_udp_payload_limit_with_edns),
        cmocka_unit_test(test_udp_payload_limit_invalid),
        cmocka_unit_test(test_response_min_ttl_single),
        cmocka_unit_test(test_response_min_ttl_multiple),
        cmocka_unit_test(test_response_min_ttl_nxdomain),
        cmocka_unit_test(test_adjust_response_ttls),
        cmocka_unit_test(test_adjust_response_ttls_clamp),
        cmocka_unit_test(test_response_is_cacheable_valid),
        cmocka_unit_test(test_response_is_cacheable_truncated),
        cmocka_unit_test(test_response_is_cacheable_servfail),
        cmocka_unit_test(test_validate_response_matching),
        cmocka_unit_test(test_validate_response_mismatched),
        cmocka_unit_test(test_validate_response_invalid),
        cmocka_unit_test(test_different_qtypes_different_keys),
        cmocka_unit_test(test_client_subnet_v4_is_reported_and_removed),
        cmocka_unit_test(test_client_subnet_v6_prefix_is_zero_padded),
        cmocka_unit_test(test_client_subnet_among_other_options),
        cmocka_unit_test(test_client_subnet_malformed_option_is_still_removed),
        cmocka_unit_test(test_client_subnet_absent_or_malformed_query),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
