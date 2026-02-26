#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>

#include "dns_message.h"
#include "test_fixtures.h"

#include "../../src/dns_message.c"

static uint32_t rng_state = 0xC0FFEEU;
static uint32_t next_rand(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

static void test_dns_message_internal_helper_branches(void **state) {
    (void)state;

    size_t off = 0;
    const uint8_t good_name[] = {0x03, 'w', 'w', 'w', 0x00};
    assert_int_equal(dns_skip_name(good_name, sizeof(good_name), &off), 0);

    off = 0;
    const uint8_t bad_label[] = {0x80, 0x00};
    assert_int_equal(dns_skip_name(bad_label, sizeof(bad_label), &off), -1);

    uint8_t long_labels[600];
    memset(long_labels, 0, sizeof(long_labels));
    size_t p = 0;
    for (int i = 0; i < 260 && p + 2 < sizeof(long_labels); i++) {
        long_labels[p++] = 1;
        long_labels[p++] = 'a';
    }
    long_labels[p++] = 0;
    off = 0;
    assert_int_equal(dns_skip_name(long_labels, p, &off), -1);

    uint8_t canonical[256];
    size_t canonical_len = 0;
    off = 0;
    assert_int_equal(dns_copy_name_canonical(good_name, sizeof(good_name), &off, canonical, sizeof(canonical), &canonical_len), 0);
    assert_true(canonical_len > 0);

    assert_int_equal(dns_message_end_offset(NULL, 0, NULL), -1);
    size_t end = 0;
    assert_int_equal(dns_message_end_offset(good_name, sizeof(good_name), &end), -1);
}

static void test_dns_message_internal_success_and_mutation_paths(void **state) {
    (void)state;

    size_t end = 0;
    assert_int_equal(dns_message_end_offset(DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN, &end), 0);
    assert_true(end <= DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);

    uint16_t an_count = 0;
    size_t rr_off = 0;
    assert_int_equal(dns_iterate_rrs(DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN, &an_count, &rr_off), 0);
    assert_true(an_count >= 1);

    assert_int_equal(dns_is_negative_response(DNS_RESPONSE_NXDOMAIN, DNS_RESPONSE_NXDOMAIN_LEN), 1);
    assert_int_equal(dns_is_negative_response(DNS_RESPONSE_SERVFAIL, DNS_RESPONSE_SERVFAIL_LEN), 0);

    uint32_t soa_min = dns_extract_soa_minimum(DNS_RESPONSE_NXDOMAIN, DNS_RESPONSE_NXDOMAIN_LEN);
    assert_true(soa_min > 0);

    assert_int_equal(dns_validate_section_counts(DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN), 0);

    uint8_t mutated[DNS_RESPONSE_NXDOMAIN_LEN];
    memset(mutated, 0, sizeof(mutated));
    memcpy(mutated, DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    mutated[6] = 0x00;
    mutated[7] = 0x05; /* ANCOUNT too large for packet */
    assert_int_equal(dns_validate_section_counts(mutated, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN), -1);

    memcpy(mutated, DNS_RESPONSE_NXDOMAIN, DNS_RESPONSE_NXDOMAIN_LEN);
    mutated[10] = 0x00;
    mutated[11] = 0x10; /* ARCOUNT too large */
    assert_int_equal(dns_validate_section_counts(mutated, DNS_RESPONSE_NXDOMAIN_LEN), -1);
}

static void test_dns_message_targeted_branch_edges(void **state) {
    (void)state;

    int ok = 0;
    /* rr_total == 0 path */
    uint32_t ttl = dns_response_min_ttl(DNS_RESPONSE_SERVFAIL, DNS_RESPONSE_SERVFAIL_LEN, &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 0);

    /* OPT-only additional section -> ttl_rr_count == 0 path */
    uint8_t opt_only[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN];
    memcpy(opt_only, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, sizeof(opt_only));
    opt_only[2] = 0x81;
    opt_only[3] = 0x80;
    ttl = dns_response_min_ttl(opt_only, sizeof(opt_only), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 0);

    /* dns_adjust_response_ttls malformed paths */
    uint8_t malformed1[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x40};
    assert_int_equal(dns_adjust_response_ttls(malformed1, sizeof(malformed1), 5), -1);
    uint8_t malformed2[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x00};
    assert_int_equal(dns_adjust_response_ttls(malformed2, sizeof(malformed2), 5), -1);

    /* validate_section_counts offset != message_len branch */
    uint8_t with_trailing[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN + 1];
    memcpy(with_trailing, DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    with_trailing[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN] = 0xEE;
    assert_int_equal(dns_validate_section_counts(with_trailing, sizeof(with_trailing)), -1);

    /* cacheable rejection branches */
    assert_int_equal(dns_response_is_cacheable(DNS_RESPONSE_TRUNCATED, DNS_RESPONSE_TRUNCATED_LEN), 0);
    uint8_t bad_rcode[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_rcode, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(bad_rcode));
    bad_rcode[3] = (uint8_t)((bad_rcode[3] & 0xF0u) | 0x02u);
    assert_int_equal(dns_response_is_cacheable(bad_rcode, sizeof(bad_rcode)), 0);

    /* validate_response_for_query branch rejects */
    uint8_t resp_no_qr[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(resp_no_qr, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(resp_no_qr));
    resp_no_qr[2] &= (uint8_t)~0x80u;
    assert_int_equal(dns_validate_response_for_query(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, resp_no_qr, sizeof(resp_no_qr)), -1);

    uint8_t resp_bad_opcode[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(resp_bad_opcode, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(resp_bad_opcode));
    resp_bad_opcode[2] ^= 0x08u;
    assert_int_equal(dns_validate_response_for_query(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, resp_bad_opcode, sizeof(resp_bad_opcode)), -1);

    uint8_t resp_bad_question[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(resp_bad_question, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(resp_bad_question));
    resp_bad_question[20] = 0x1C;
    assert_int_equal(dns_validate_response_for_query(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, resp_bad_question, sizeof(resp_bad_question)), -1);
}

static void test_dns_message_additional_internal_edges(void **state) {
    (void)state;

    size_t off = 0;
    size_t out_len = 0;
    uint8_t out[8];
    assert_int_equal(dns_copy_name_canonical(NULL, 0, &off, out, sizeof(out), &out_len), -1);

    const uint8_t ptr_loop[] = {0xC0, 0x00};
    off = 0;
    assert_int_equal(dns_copy_name_canonical(ptr_loop, sizeof(ptr_loop), &off, out, sizeof(out), &out_len), -1);

    uint8_t overflow_hdr[12] = {0};
    overflow_hdr[6] = 0xFF;
    overflow_hdr[7] = 0xFF;
    overflow_hdr[8] = 0x00;
    overflow_hdr[9] = 0x01;
    size_t end = 0;
    assert_int_equal(dns_message_end_offset(overflow_hdr, sizeof(overflow_hdr), &end), -1);

    uint8_t bad_qd[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_qd, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_qd));
    bad_qd[4] = 0;
    bad_qd[5] = 0;
    size_t key_len = 0;
    assert_int_equal(dns_extract_question_key(bad_qd, sizeof(bad_qd), out, sizeof(out), &key_len), -1);

    uint8_t bad_opcode[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_opcode, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_opcode));
    bad_opcode[2] |= 0x08;
    assert_int_equal(dns_extract_question_key(bad_opcode, sizeof(bad_opcode), out, sizeof(out), &key_len), -1);

    uint8_t non_opt_additional[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN + 11];
    memcpy(non_opt_additional, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    non_opt_additional[10] = 0x00;
    non_opt_additional[11] = 0x01;
    size_t p = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x01;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x01;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x00;
    non_opt_additional[p++] = 0x00;
    assert_int_equal(dns_extract_question_key(non_opt_additional, p, out, sizeof(out), &key_len), -1);

    uint8_t duplicate_opt[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 11];
    memcpy(duplicate_opt, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN);
    duplicate_opt[10] = 0x00;
    duplicate_opt[11] = 0x02;
    memcpy(duplicate_opt + DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
           DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS + DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN - 11,
           11);
    assert_int_equal(dns_extract_question_key(duplicate_opt, sizeof(duplicate_opt), out, sizeof(out), &key_len), -1);

    size_t opt_rr = 12;
    assert_int_equal(dns_skip_name(DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN, &opt_rr), 0);
    opt_rr += 4;

    uint8_t low_payload[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN];
    memcpy(low_payload, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, sizeof(low_payload));
    low_payload[opt_rr + 3] = 0x01;
    low_payload[opt_rr + 4] = 0xF4;
    assert_int_equal(dns_udp_payload_limit_for_query(low_payload, sizeof(low_payload)), 512);

    uint8_t hi_payload[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN];
    memcpy(hi_payload, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, sizeof(hi_payload));
    hi_payload[opt_rr + 3] = 0xFF;
    hi_payload[opt_rr + 4] = 0xFF;
    assert_int_equal(dns_udp_payload_limit_for_query(hi_payload, sizeof(hi_payload)), 4096);

    uint8_t ttl_msg[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(ttl_msg, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(ttl_msg));
    assert_int_equal(dns_adjust_response_ttls(ttl_msg, sizeof(ttl_msg), 400), 0);
    assert_int_equal(ttl_msg[39], 0x00);
    assert_int_equal(ttl_msg[40], 0x00);
    assert_int_equal(ttl_msg[41], 0x00);
    assert_int_equal(ttl_msg[42], 0x00);

    int ok = 0;
    assert_int_equal(dns_response_min_ttl(DNS_RESPONSE_MULTI_ANSWER, DNS_RESPONSE_MULTI_ANSWER_LEN, &ok), 100);
    assert_int_equal(ok, 1);

    size_t opt_rr2 = 12;
    assert_int_equal(dns_skip_name(DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN, &opt_rr2), 0);
    opt_rr2 += 4;

    uint8_t edns_opts[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 16];
    memcpy(edns_opts, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN);
    size_t edns_len = DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN;
    edns_opts[opt_rr2 + 9] = 0x00;
    edns_opts[opt_rr2 + 10] = 0x08;
    edns_opts[edns_len + 0] = 0x00;
    edns_opts[edns_len + 1] = 0x0F;
    edns_opts[edns_len + 2] = 0x00;
    edns_opts[edns_len + 3] = 0x04;
    edns_opts[edns_len + 4] = 0xDE;
    edns_opts[edns_len + 5] = 0xAD;
    edns_opts[edns_len + 6] = 0xBE;
    edns_opts[edns_len + 7] = 0xEF;
    edns_len += 8;

    uint8_t keybuf[512];
    size_t keylen = 0;
    assert_int_equal(dns_extract_question_key(edns_opts, edns_len, keybuf, sizeof(keybuf), &keylen), 0);
    assert_true(keylen > 0);

    uint8_t edns_bad_hdr[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 2];
    memcpy(edns_bad_hdr, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN);
    edns_bad_hdr[opt_rr2 + 9] = 0x00;
    edns_bad_hdr[opt_rr2 + 10] = 0x02;
    edns_bad_hdr[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 0] = 0x00;
    edns_bad_hdr[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 1] = 0x0F;
    assert_int_equal(dns_extract_question_key(edns_bad_hdr, sizeof(edns_bad_hdr), keybuf, sizeof(keybuf), &keylen), -1);

    uint8_t edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 6];
    memcpy(edns_bad_len, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN);
    edns_bad_len[opt_rr2 + 9] = 0x00;
    edns_bad_len[opt_rr2 + 10] = 0x06;
    edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 0] = 0x00;
    edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 1] = 0x0F;
    edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 2] = 0x00;
    edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 3] = 0x10;
    edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 4] = 0xAA;
    edns_bad_len[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN + 5] = 0xBB;
    assert_int_equal(dns_extract_question_key(edns_bad_len, sizeof(edns_bad_len), keybuf, sizeof(keybuf), &keylen), -1);
}

static void test_dns_message_randomized_branch_exploration(void **state) {
    (void)state;

    uint8_t msg[512];
    uint8_t query[512];
    uint8_t out[512];

    for (int i = 0; i < 200000; i++) {
        size_t len = (size_t)(next_rand() % sizeof(msg));
        for (size_t j = 0; j < len; j++) {
            msg[j] = (uint8_t)(next_rand() & 0xFFu);
            query[j] = (uint8_t)(next_rand() & 0xFFu);
        }

        size_t key_len = 0;
        (void)dns_extract_question_key(msg, len, out, sizeof(out), &key_len);

        size_t qlen = 0;
        (void)dns_question_section_length(msg, len, &qlen);

        (void)dns_udp_payload_limit_for_query(msg, len);

        int ok = 0;
        (void)dns_response_min_ttl(msg, len, &ok);

        uint8_t tmp[512];
        if (len <= sizeof(tmp)) {
            memcpy(tmp, msg, len);
            (void)dns_adjust_response_ttls(tmp, len, (uint32_t)(next_rand() % 1000));
        }

        (void)dns_response_is_cacheable(msg, len);
        (void)dns_validate_response_for_query(query, len, msg, len);
    }
}

static void test_dns_message_rr_parsing_error_edges(void **state) {
    (void)state;

    int ok = 0;

    uint8_t bad_rr_name[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x00, /* qd */
        0x00, 0x01, /* an */
        0x00, 0x00, 0x00, 0x00,
        0x80
    };
    assert_int_equal(dns_response_min_ttl(bad_rr_name, sizeof(bad_rr_name), &ok), 0);

    uint8_t short_rr_hdr[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00
    };
    assert_int_equal(dns_response_min_ttl(short_rr_hdr, sizeof(short_rr_hdr), &ok), 0);

    uint8_t rr_rdlen_over[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0xFF, 0xFF
    };
    assert_int_equal(dns_response_min_ttl(rr_rdlen_over, sizeof(rr_rdlen_over), &ok), 0);

    uint8_t adj_bad_name[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x80
    };
    assert_int_equal(dns_adjust_response_ttls(adj_bad_name, sizeof(adj_bad_name), 1), -1);

    uint8_t adj_short_hdr[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00
    };
    assert_int_equal(dns_adjust_response_ttls(adj_short_hdr, sizeof(adj_short_hdr), 1), -1);

    uint8_t adj_rdlen_over[] = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0xFF, 0xFF
    };
    assert_int_equal(dns_adjust_response_ttls(adj_rdlen_over, sizeof(adj_rdlen_over), 1), -1);

    uint8_t response_trailing[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN + 1];
    memcpy(response_trailing, DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    response_trailing[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN] = 0x7A;
    assert_int_equal(
        dns_validate_response_for_query(
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            response_trailing,
            sizeof(response_trailing)),
        -1);

    uint8_t response_bad_counts[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(response_bad_counts, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(response_bad_counts));
    response_bad_counts[6] = 0x00;
    response_bad_counts[7] = 0x03;
    assert_int_equal(
        dns_validate_response_for_query(
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            response_bad_counts,
            sizeof(response_bad_counts)),
        -1);
}

static void test_dns_message_misc_guard_and_capacity_edges(void **state) {
    (void)state;

    size_t off = 0;
    const uint8_t ptr_trunc[] = {0xC0};
    assert_int_equal(dns_skip_name(ptr_trunc, sizeof(ptr_trunc), &off), -1);

    uint8_t name_msg[] = {0x03, 'w', 'w', 'w', 0x00};
    uint8_t out[4];
    size_t out_len = 0;
    off = 0;
    assert_int_equal(dns_copy_name_canonical(name_msg, sizeof(name_msg), &off, out, sizeof(out), &out_len), -1);

    uint8_t bad_qtail[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN - 1];
    memcpy(bad_qtail, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_qtail));
    size_t end = 0;
    assert_int_equal(dns_message_end_offset(bad_qtail, sizeof(bad_qtail), &end), -1);

    uint8_t bad_rdlen[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_rdlen, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(bad_rdlen));
    bad_rdlen[43] = 0xFF;
    bad_rdlen[44] = 0xFF;
    assert_int_equal(dns_message_end_offset(bad_rdlen, sizeof(bad_rdlen), &end), -1);

    uint8_t tiny_key[4];
    size_t key_len = 0;
    assert_int_equal(dns_extract_question_key(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, tiny_key, sizeof(tiny_key), &key_len), -1);

    uint8_t extra_tail[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN + 1];
    memcpy(extra_tail, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    extra_tail[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN] = 0x99;
    uint8_t keybuf[512];
    assert_int_equal(dns_extract_question_key(extra_tail, sizeof(extra_tail), keybuf, sizeof(keybuf), &key_len), -1);

    uint8_t bad_qsec[13] = {
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x80
    };
    size_t qsec_len = 0;
    assert_int_equal(dns_question_section_length(bad_qsec, sizeof(bad_qsec), &qsec_len), -1);

    assert_int_equal(dns_validate_section_counts(NULL, 0), -1);
    assert_int_equal(dns_response_is_cacheable(NULL, 0), 0);

    uint8_t short_q[11] = {0};
    assert_int_equal(dns_validate_response_for_query(short_q, sizeof(short_q), DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN), -1);
}

static void test_dns_message_more_malformed_edges(void **state) {
    (void)state;

    size_t off = 0;
    size_t out_len = 0;
    uint8_t outbuf[32];

    const uint8_t ptr_oob[] = {0xC0, 0xFF, 0x00};
    off = 0;
    assert_int_equal(dns_copy_name_canonical(ptr_oob, sizeof(ptr_oob), &off, outbuf, sizeof(outbuf), &out_len), -1);

    const uint8_t no_term[] = {0x01, 'a'};
    off = 0;
    assert_int_equal(dns_copy_name_canonical(no_term, sizeof(no_term), &off, outbuf, sizeof(outbuf), &out_len), -1);

    uint8_t qd_mismatch_q[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(qd_mismatch_q, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(qd_mismatch_q));
    uint8_t qd_mismatch_r[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(qd_mismatch_r, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(qd_mismatch_r));
    qd_mismatch_r[4] = 0x00;
    qd_mismatch_r[5] = 0x00;
    assert_int_equal(dns_validate_response_for_query(qd_mismatch_q, sizeof(qd_mismatch_q), qd_mismatch_r, sizeof(qd_mismatch_r)), -1);

    uint8_t q_short_tail[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(q_short_tail, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(q_short_tail));
    q_short_tail[0] = 0x00; /* no-op mutation, keep shape */
    uint8_t r_short_tail[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(r_short_tail, DNS_RESPONSE_WWW_EXAMPLE_COM_A, sizeof(r_short_tail));
    r_short_tail[29] = 0x00;
    r_short_tail[30] = 0x02; /* inflate QTYPE/QCLASS mismatch path */
    assert_int_equal(dns_validate_response_for_query(q_short_tail, sizeof(q_short_tail), r_short_tail, sizeof(r_short_tail)), -1);

    uint8_t ar_bad_name[13] = {
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x80
    };
    size_t key_len = 0;
    assert_int_equal(dns_extract_question_key(ar_bad_name, sizeof(ar_bad_name), outbuf, sizeof(outbuf), &key_len), -1);

    uint8_t ar_short_hdr[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN + 1];
    memcpy(ar_short_hdr, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    ar_short_hdr[10] = 0x00;
    ar_short_hdr[11] = 0x01;
    ar_short_hdr[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN] = 0x00;
    assert_int_equal(dns_extract_question_key(ar_short_hdr, sizeof(ar_short_hdr), outbuf, sizeof(outbuf), &key_len), -1);

    uint8_t bad_qsec_tail[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN - 2];
    memcpy(bad_qsec_tail, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_qsec_tail));
    size_t qsec = 0;
    assert_int_equal(dns_question_section_length(bad_qsec_tail, sizeof(bad_qsec_tail), &qsec), -1);

    uint8_t udp_bad_q[13] = {
        0x12, 0x34, 0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x80
    };
    assert_int_equal(dns_udp_payload_limit_for_query(udp_bad_q, sizeof(udp_bad_q)), 512);

    uint8_t soa_bad_q[13] = {
        0x12, 0x34, 0x81, 0x83,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x80
    };
    int ok = 0;
    assert_int_equal(dns_response_min_ttl(soa_bad_q, sizeof(soa_bad_q), &ok), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dns_message_internal_helper_branches),
        cmocka_unit_test(test_dns_message_internal_success_and_mutation_paths),
        cmocka_unit_test(test_dns_message_targeted_branch_edges),
        cmocka_unit_test(test_dns_message_additional_internal_edges),
        cmocka_unit_test(test_dns_message_randomized_branch_exploration),
        cmocka_unit_test(test_dns_message_rr_parsing_error_edges),
        cmocka_unit_test(test_dns_message_misc_guard_and_capacity_edges),
        cmocka_unit_test(test_dns_message_more_malformed_edges),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
