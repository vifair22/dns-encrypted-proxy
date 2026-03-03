#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void test_write_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void test_write_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xffu);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static int g_test_rand_value = 0xBEEF;
static int iterative_test_rand(void) {
    return g_test_rand_value;
}

#define DNS_PORT 15353
#define rand iterative_test_rand
#include "../../src/iterative_resolver.c"
#undef rand

static size_t write_qname_example_com(uint8_t *out) {
    size_t off = 0;
    out[off++] = 7; memcpy(out + off, "example", 7); off += 7;
    out[off++] = 3; memcpy(out + off, "com", 3); off += 3;
    out[off++] = 0;
    return off;
}

static void sleep_ms(unsigned int ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
    (void)nanosleep(&ts, NULL);
}

static void test_normalize_hostname(void **state) {
    (void)state;
    char out[256];

    assert_int_equal(normalize_hostname(" Example.COM. ", out, sizeof(out)), 0);
    assert_string_equal(out, "example.com");

    assert_int_equal(normalize_hostname("", out, sizeof(out)), -1);
    assert_int_equal(normalize_hostname("   ", out, sizeof(out)), -1);
}

static void test_encode_qname(void **state) {
    (void)state;
    uint8_t out[64];
    size_t written = 0;

    assert_int_equal(encode_qname("example.com", out, sizeof(out), &written), 0);
    assert_true(written > 0);
    assert_int_equal(out[0], 7);
    assert_int_equal(out[8], 3);

    char long_label[80];
    memset(long_label, 'a', 70);
    long_label[70] = '\0';
    assert_int_equal(encode_qname(long_label, out, sizeof(out), &written), -1);
}

static void test_cache_store_lookup_and_expire(void **state) {
    (void)state;
    memset(g_cache, 0, sizeof(g_cache));

    struct in_addr a;
    assert_int_equal(inet_pton(AF_INET, "8.8.8.8", &a), 1);
    cache_store("dns.google", a.s_addr, 30);

    uint32_t got = 0;
    assert_int_equal(cache_lookup("dns.google", &got), 1);
    assert_int_equal(got, a.s_addr);

    pthread_mutex_lock(&g_cache_mutex);
    for (int i = 0; i < ITER_CACHE_ENTRIES; i++) {
        if (g_cache[i].in_use && strcmp(g_cache[i].host, "dns.google") == 0) {
            g_cache[i].expires_at_ms = 0;
        }
    }
    pthread_mutex_unlock(&g_cache_mutex);

    assert_int_equal(cache_lookup("dns.google", &got), 0);
}

static void test_parse_response_for_name_a_answer(void **state) {
    (void)state;

    uint8_t msg[128];
    memset(msg, 0, sizeof(msg));

    test_write_u16(msg + 0, 0x1234);
    test_write_u16(msg + 2, 0x8180);
    test_write_u16(msg + 4, 1);
    test_write_u16(msg + 6, 1);

    size_t off = DNS_HEADER_SIZE;
    off += write_qname_example_com(msg + off);
    test_write_u16(msg + off, DNS_TYPE_A);
    test_write_u16(msg + off + 2, DNS_CLASS_IN);
    off += 4;

    msg[off++] = 0xC0;
    msg[off++] = 0x0C;
    test_write_u16(msg + off, DNS_TYPE_A);
    test_write_u16(msg + off + 2, DNS_CLASS_IN);
    test_write_u32(msg + off + 4, 60);
    test_write_u16(msg + off + 8, 4);
    off += 10;
    msg[off++] = 1;
    msg[off++] = 2;
    msg[off++] = 3;
    msg[off++] = 4;

    parsed_response_t parsed;
    assert_int_equal(parse_response_for_name(msg, off, "example.com", &parsed), 0);
    assert_int_equal(parsed.got_a, 1);
    assert_int_equal(parsed.a_ttl, 60);

    struct in_addr got;
    got.s_addr = parsed.a_addr_be;
    assert_string_equal(inet_ntoa(got), "1.2.3.4");
}

static void test_build_query_and_iterative_cache_hit(void **state) {
    (void)state;

    uint8_t query[512];
    size_t written = 0;
    assert_int_equal(build_query_packet("example.com", DNS_TYPE_A, 0x2222, query, sizeof(query), &written), 0);
    assert_true(written > DNS_HEADER_SIZE);

    memset(g_cache, 0, sizeof(g_cache));
    struct in_addr a;
    assert_int_equal(inet_pton(AF_INET, "9.9.9.9", &a), 1);
    cache_store("example.com", a.s_addr, 30);

    uint32_t out = 0;
    assert_int_equal(iterative_resolve_a("example.com", 200, &out), 0);
    assert_int_equal(out, a.s_addr);

    assert_int_equal(iterative_resolve_a("", 200, &out), -1);
}

static void test_skip_and_read_name_error_paths(void **state) {
    (void)state;

    uint8_t msg[32];
    memset(msg, 0, sizeof(msg));

    size_t off = 0;
    msg[0] = 0xC0;
    assert_int_equal(skip_name(msg, 1, &off), -1);

    off = 0;
    msg[0] = 3;
    memcpy(msg + 1, "abc", 3);
    msg[4] = 0;
    char out[8];
    assert_int_equal(read_name(msg, sizeof(msg), &off, out, sizeof(out)), 0);
    assert_string_equal(out, "abc");

    off = 0;
    msg[0] = 0xC0;
    msg[1] = 0xFF;
    assert_int_equal(read_name(msg, sizeof(msg), &off, out, sizeof(out)), -1);
}

static void test_parse_response_nxdomain_and_referral(void **state) {
    (void)state;

    uint8_t msg[256];
    memset(msg, 0, sizeof(msg));
    write_u16(msg + 0, 0x1111);
    write_u16(msg + 2, 0x8183);
    write_u16(msg + 4, 1);
    size_t off = DNS_HEADER_SIZE;
    off += write_qname_example_com(msg + off);
    test_write_u16(msg + off, DNS_TYPE_A);
    test_write_u16(msg + off + 2, DNS_CLASS_IN);
    off += 4;

    parsed_response_t parsed;
    assert_int_equal(parse_response_for_name(msg, off, "example.com", &parsed), 0);
    assert_int_equal(parsed.got_a, 0);

    memset(msg, 0, sizeof(msg));
    write_u16(msg + 0, 0x2222);
    write_u16(msg + 2, 0x8180);
    write_u16(msg + 4, 1);
    write_u16(msg + 8, 1);
    write_u16(msg + 10, 1);
    off = DNS_HEADER_SIZE;
    off += write_qname_example_com(msg + off);
    test_write_u16(msg + off, DNS_TYPE_A);
    test_write_u16(msg + off + 2, DNS_CLASS_IN);
    off += 4;

    /* NS in authority */
    msg[off++] = 0xC0;
    msg[off++] = 0x0C;
    test_write_u16(msg + off, DNS_TYPE_NS);
    test_write_u16(msg + off + 2, DNS_CLASS_IN);
    test_write_u32(msg + off + 4, 300);
    size_t rdlen_pos = off + 8;
    off += 10;
    size_t ns_start = off;
    msg[off++] = 2; memcpy(msg + off, "ns", 2); off += 2;
    msg[off++] = 7; memcpy(msg + off, "example", 7); off += 7;
    msg[off++] = 3; memcpy(msg + off, "com", 3); off += 3;
    msg[off++] = 0;
    test_write_u16(msg + rdlen_pos, (uint16_t)(off - ns_start));

    /* Glue A for ns.example.com */
    msg[off++] = 2; memcpy(msg + off, "ns", 2); off += 2;
    msg[off++] = 7; memcpy(msg + off, "example", 7); off += 7;
    msg[off++] = 3; memcpy(msg + off, "com", 3); off += 3;
    msg[off++] = 0;
    test_write_u16(msg + off, DNS_TYPE_A);
    test_write_u16(msg + off + 2, DNS_CLASS_IN);
    test_write_u32(msg + off + 4, 300);
    test_write_u16(msg + off + 8, 4);
    off += 10;
    msg[off++] = 9;
    msg[off++] = 9;
    msg[off++] = 9;
    msg[off++] = 9;

    assert_int_equal(parse_response_for_name(msg, off, "example.com", &parsed), 0);
    assert_int_equal(parsed.ns_name_count, 1);
    assert_int_equal(parsed.glue_count, 1);
}

static void test_send_helpers_socketpair(void **state) {
    (void)state;

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    uint8_t tx[4] = {1, 2, 3, 4};
    uint8_t rx[4] = {0};
    assert_int_equal(send_all_with_timeout(sv[0], tx, sizeof(tx), 100), 0);
    assert_int_equal(recv_all_with_timeout(sv[1], rx, sizeof(rx), 100), 0);
    assert_memory_equal(tx, rx, sizeof(tx));

    close(sv[1]);
    assert_int_equal(send_all_with_timeout(sv[0], tx, sizeof(tx), 100), -1);
    close(sv[0]);
}

typedef struct {
    uint8_t response[512];
    size_t response_len;
    int use_tcp;
} local_dns_server_ctx_t;

static void *local_dns_server_once(void *arg) {
    local_dns_server_ctx_t *ctx = (local_dns_server_ctx_t *)arg;
    int fd = socket(AF_INET, ctx->use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    assert_true(fd >= 0);

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(DNS_PORT);
    assert_int_equal(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

    if (ctx->use_tcp) {
        assert_int_equal(listen(fd, 1), 0);
        int cfd = accept(fd, NULL, NULL);
        assert_true(cfd >= 0);

        uint8_t len_prefix[2];
        assert_int_equal(recv(cfd, len_prefix, 2, MSG_WAITALL), 2);
        uint16_t qlen = read_u16(len_prefix);
        uint8_t qbuf[512];
        assert_true(qlen <= sizeof(qbuf));
        assert_int_equal(recv(cfd, qbuf, qlen, MSG_WAITALL), (int)qlen);

        uint8_t out_len[2];
        test_write_u16(out_len, (uint16_t)ctx->response_len);
        assert_int_equal(send(cfd, out_len, 2, 0), 2);
        assert_int_equal(send(cfd, ctx->response, ctx->response_len, 0), (int)ctx->response_len);
        close(cfd);
    } else {
        uint8_t qbuf[512];
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        ssize_t n = recvfrom(fd, qbuf, sizeof(qbuf), 0, (struct sockaddr *)&cli, &clen);
        assert_true(n >= 12);
        assert_int_equal(sendto(fd, ctx->response, ctx->response_len, 0, (struct sockaddr *)&cli, clen), (int)ctx->response_len);
    }

    close(fd);
    return NULL;
}

static void test_send_udp_query_success_and_truncated(void **state) {
    (void)state;

    local_dns_server_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    uint8_t resp[64];
    memset(resp, 0, sizeof(resp));
    test_write_u16(resp + 0, 0xBEEF);
    test_write_u16(resp + 2, 0x8180);
    test_write_u16(resp + 4, 1);
    size_t roff = DNS_HEADER_SIZE;
    roff += write_qname_example_com(resp + roff);
    test_write_u16(resp + roff, DNS_TYPE_A);
    test_write_u16(resp + roff + 2, DNS_CLASS_IN);
    roff += 4;
    memcpy(ctx.response, resp, roff);
    ctx.response_len = roff;
    ctx.use_tcp = 0;

    pthread_t t;
    assert_int_equal(pthread_create(&t, NULL, local_dns_server_once, &ctx), 0);
    sleep_ms(50);

    struct in_addr ip;
    assert_int_equal(inet_pton(AF_INET, "127.0.0.1", &ip), 1);
    uint8_t out[512];
    size_t out_len = 0;
    int truncated = 0;
    assert_int_equal(send_udp_query(ip.s_addr, "example.com", DNS_TYPE_A, 500, out, sizeof(out), &out_len, &truncated), 0);
    assert_int_equal(truncated, 0);
    assert_true(out_len >= DNS_HEADER_SIZE);
    pthread_join(t, NULL);

    memset(resp, 0, sizeof(resp));
    test_write_u16(resp + 0, 0xBEEF);
    test_write_u16(resp + 2, 0x8200); /* TC bit set */
    memcpy(ctx.response, resp, DNS_HEADER_SIZE);
    ctx.response_len = DNS_HEADER_SIZE;

    assert_int_equal(pthread_create(&t, NULL, local_dns_server_once, &ctx), 0);
    sleep_ms(50);
    out_len = 0;
    truncated = 0;
    assert_int_equal(send_udp_query(ip.s_addr, "example.com", DNS_TYPE_A, 500, out, sizeof(out), &out_len, &truncated), 0);
    assert_int_equal(truncated, 1);
    pthread_join(t, NULL);
}

static void test_send_tcp_query_invalid_path(void **state) {
    (void)state;
    struct in_addr ip;
    assert_int_equal(inet_pton(AF_INET, "127.0.0.1", &ip), 1);

    uint8_t out[32];
    size_t out_len = 0;
    assert_int_equal(send_tcp_query(ip.s_addr, "example.com", DNS_TYPE_A, 50, out, sizeof(out), &out_len), -1);
}

static void test_iterative_guard_paths(void **state) {
    (void)state;

    uint8_t namebuf[16];
    size_t written = 0;
    assert_int_equal(encode_qname(NULL, namebuf, sizeof(namebuf), &written), -1);
    assert_int_equal(encode_qname("a", NULL, sizeof(namebuf), &written), -1);
    assert_int_equal(encode_qname("a", namebuf, sizeof(namebuf), NULL), -1);

    size_t off = 0;
    assert_int_equal(skip_name(NULL, 0, &off), -1);
    assert_int_equal(skip_name(namebuf, sizeof(namebuf), NULL), -1);

    char out_name[16];
    assert_int_equal(read_name(NULL, 0, &off, out_name, sizeof(out_name)), -1);
    assert_int_equal(read_name(namebuf, sizeof(namebuf), NULL, out_name, sizeof(out_name)), -1);
    assert_int_equal(read_name(namebuf, sizeof(namebuf), &off, NULL, sizeof(out_name)), -1);

    ip_list_t list;
    memset(&list, 0, sizeof(list));
    for (int i = 0; i < ITER_MAX_NS; i++) {
        assert_int_equal(ip_list_add(&list, (uint32_t)(i + 1)), 0);
    }
    assert_int_equal(ip_list_add(&list, 123456u), -1);

    assert_int_equal(cache_lookup(NULL, NULL), 0);
    cache_store(NULL, 0, 0);

    parsed_response_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    assert_int_equal(ns_name_present(&parsed, "x"), 0);
    assert_int_equal(ns_name_present(NULL, "x"), 0);

    assert_int_equal(build_query_packet(NULL, DNS_TYPE_A, 1, namebuf, sizeof(namebuf), &written), -1);

    size_t out_len = 0;
    int truncated = 0;
    assert_int_equal(send_udp_query(0, NULL, DNS_TYPE_A, 1, namebuf, sizeof(namebuf), &out_len, &truncated), -1);

    assert_int_equal(send_all_with_timeout(-1, namebuf, sizeof(namebuf), 1), -1);
    assert_int_equal(recv_all_with_timeout(-1, namebuf, sizeof(namebuf), 1), -1);

    assert_int_equal(parse_response_for_name(NULL, 0, "example.com", &parsed), -1);
    assert_int_equal(parse_response_for_name(namebuf, 0, "example.com", &parsed), -1);

    uint32_t a = 0;
    assert_int_equal(iterative_resolve_a(NULL, 10, &a), -1);
    assert_int_equal(iterative_resolve_a("example.com", 10, NULL), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_normalize_hostname),
        cmocka_unit_test(test_encode_qname),
        cmocka_unit_test(test_cache_store_lookup_and_expire),
        cmocka_unit_test(test_parse_response_for_name_a_answer),
        cmocka_unit_test(test_build_query_and_iterative_cache_hit),
        cmocka_unit_test(test_skip_and_read_name_error_paths),
        cmocka_unit_test(test_parse_response_nxdomain_and_referral),
        cmocka_unit_test(test_send_helpers_socketpair),
        cmocka_unit_test(test_send_udp_query_success_and_truncated),
        cmocka_unit_test(test_send_tcp_query_invalid_path),
        cmocka_unit_test(test_iterative_guard_paths),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
