#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "upstream.h"
#include "iterative_resolver.h"

static proxy_status_t g_iter_rc = PROXY_ERR_NETWORK;
static uint32_t g_iter_addr = 0;

proxy_status_t iterative_resolve_a(const char *hostname, int timeout_ms, uint32_t *addr_v4_be_out) {
    (void)hostname;
    (void)timeout_ms;
    if (g_iter_rc == PROXY_OK && addr_v4_be_out != NULL) {
        *addr_v4_be_out = g_iter_addr;
    }
    return g_iter_rc;
}

#define BOOTSTRAP_DNS_PORT 15353
#include "../../src/upstream_bootstrap.c"

typedef struct {
    uint32_t answer_ip_be;
    uint32_t answer_ttl;
    volatile int ready;
} dns_server_ctx_t;

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

static void sleep_ms(unsigned int ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
    (void)nanosleep(&ts, NULL);
}

static void *dns_server_once(void *arg) {
    dns_server_ctx_t *ctx = (dns_server_ctx_t *)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NULL;
    }

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(BOOTSTRAP_DNS_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return NULL;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ctx->ready = 1;

    uint8_t query[512];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t qn = recvfrom(fd, query, sizeof(query), 0, (struct sockaddr *)&peer, &peer_len);
    if (qn < 12) {
        close(fd);
        return NULL;
    }

    size_t qoff = 12;
    while (qoff < (size_t)qn && query[qoff] != 0) {
        uint8_t ll = query[qoff];
        if (ll > 63 || qoff + 1 + ll >= (size_t)qn) {
            close(fd);
            return NULL;
        }
        qoff += 1 + ll;
    }
    if (qoff + 5 > (size_t)qn) {
        close(fd);
        return NULL;
    }
    qoff += 1 + 4;

    uint8_t resp[512];
    memset(resp, 0, sizeof(resp));
    test_write_u16(resp + 0, read_u16(query + 0));
    test_write_u16(resp + 2, 0x8180);
    test_write_u16(resp + 4, 1);
    test_write_u16(resp + 6, 1);

    size_t roff = 12;
    memcpy(resp + roff, query + 12, qoff - 12);
    roff += (qoff - 12);

    resp[roff++] = 0xC0;
    resp[roff++] = 0x0C;
    test_write_u16(resp + roff, 1);
    test_write_u16(resp + roff + 2, 1);
    test_write_u32(resp + roff + 4, ctx->answer_ttl);
    test_write_u16(resp + roff + 8, 4);
    roff += 10;
    memcpy(resp + roff, &ctx->answer_ip_be, 4);
    roff += 4;

    (void)sendto(fd, resp, roff, 0, (struct sockaddr *)&peer, peer_len);
    close(fd);
    return NULL;
}

static void reset_stubs(void) {
    g_iter_rc = -1;
    g_iter_addr = 0;
}

static void test_configure_paths(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    memset(&client, 0, sizeof(client));
    proxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.bootstrap_resolver_count = 2;
    strcpy(cfg.bootstrap_resolvers[0], "8.8.8.8");
    strcpy(cfg.bootstrap_resolvers[1], "1.1.1.1");

    assert_int_equal(upstream_bootstrap_configure(&client, &cfg), PROXY_OK);
    assert_int_equal(client.bootstrap_resolver_count, 2);
    assert_string_equal(client.bootstrap_resolvers[0], "8.8.8.8");
    assert_string_equal(client.bootstrap_resolvers[1], "1.1.1.1");

    assert_int_equal(upstream_bootstrap_configure(NULL, &cfg), PROXY_ERR_INVALID_ARG);
    assert_int_equal(upstream_bootstrap_configure(&client, NULL), PROXY_ERR_INVALID_ARG);
}

static void test_stage2_no_resolvers(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    memset(&client, 0, sizeof(client));

    upstream_server_t s;
    memset(&s, 0, sizeof(s));
    strcpy(s.host, "dns.google");

    const char *reason = NULL;
    assert_int_equal(upstream_bootstrap_try_stage2(&client, &s, 100, &reason), -1);
    assert_string_equal(reason, "no_bootstrap_resolvers");
    assert_true(s.stage.stage2_next_retry_ms > now_ms());

    reason = NULL;
    assert_int_equal(upstream_bootstrap_try_stage2(&client, &s, 100, &reason), -1);
    assert_string_equal(reason, "cooldown");

    assert_int_equal(upstream_bootstrap_try_stage2(NULL, &s, 100, NULL), -1);
    assert_int_equal(upstream_bootstrap_try_stage2(&client, NULL, 100, NULL), -1);
}

static void test_stage2_success_and_ttl_clamp(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    memset(&client, 0, sizeof(client));
    client.bootstrap_resolver_count = 1;
    strcpy(client.bootstrap_resolvers[0], "127.0.0.1");

    upstream_server_t s;
    memset(&s, 0, sizeof(s));
    strcpy(s.host, "dns.google");

    dns_server_ctx_t ctx;
    struct in_addr a;
    assert_int_equal(inet_pton(AF_INET, "4.4.4.4", &a), 1);
    ctx.answer_ip_be = a.s_addr;
    ctx.answer_ttl = 1;

    pthread_t t;
    ctx.ready = 0;
    assert_int_equal(pthread_create(&t, NULL, dns_server_once, &ctx), 0);
    for (int i = 0; i < 50 && !ctx.ready; i++) {
        sleep_ms(10);
    }

    uint64_t before = now_ms();
    assert_int_equal(upstream_bootstrap_try_stage2(&client, &s, 500, NULL), 0);
    pthread_join(t, NULL);

    assert_int_equal(s.stage.has_bootstrap_v4, 1);
    assert_int_equal(s.stage.bootstrap_addr_v4_be, a.s_addr);
    assert_true(s.stage.bootstrap_expires_at_ms >= before + STAGE2_CACHE_TTL_MIN_MS);

    assert_int_equal(inet_pton(AF_INET, "4.4.8.8", &a), 1);
    ctx.answer_ip_be = a.s_addr;
    ctx.answer_ttl = 9999999;
    s.stage.bootstrap_expires_at_ms = 0;

    ctx.ready = 0;
    assert_int_equal(pthread_create(&t, NULL, dns_server_once, &ctx), 0);
    for (int i = 0; i < 50 && !ctx.ready; i++) {
        sleep_ms(10);
    }
    before = now_ms();
    assert_int_equal(upstream_bootstrap_try_stage2(&client, &s, 500, NULL), 0);
    pthread_join(t, NULL);

    assert_int_equal(s.stage.bootstrap_addr_v4_be, a.s_addr);
    assert_true(s.stage.bootstrap_expires_at_ms <= before + STAGE2_CACHE_TTL_MAX_MS + 20);
}

static void test_stage1_hydrate_success(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    memset(&client, 0, sizeof(client));
    client.bootstrap_resolver_count = 1;
    strcpy(client.bootstrap_resolvers[0], "127.0.0.1");

    upstream_server_t s;
    memset(&s, 0, sizeof(s));
    strcpy(s.host, "cloudflare-dns.com");
    s.stage.has_stage1_cached_v4 = 1;
    s.stage.stage1_cached_addr_v4_be = htonl(0x01010101u);

    dns_server_ctx_t ctx;
    struct in_addr a;
    assert_int_equal(inet_pton(AF_INET, "1.1.1.1", &a), 1);
    ctx.answer_ip_be = a.s_addr;
    ctx.answer_ttl = 120;

    pthread_t t;
    ctx.ready = 0;
    assert_int_equal(pthread_create(&t, NULL, dns_server_once, &ctx), 0);
    for (int i = 0; i < 50 && !ctx.ready; i++) {
        sleep_ms(10);
    }

    assert_int_equal(upstream_bootstrap_stage1_hydrate(&client, &s, 500), 0);
    pthread_join(t, NULL);

    assert_int_equal(s.stage.has_stage1_cached_v4, 1);
    assert_int_equal(s.stage.stage1_cached_addr_v4_be, a.s_addr);
    assert_int_equal(s.stage.has_bootstrap_v4, 1);
    assert_int_equal(s.stage.bootstrap_addr_v4_be, a.s_addr);
    assert_true(s.stage.stage1_cache_expires_at_ms != 0);
    assert_true(s.stage.bootstrap_expires_at_ms != 0);
}

static void test_stage3_success_failure_and_cooldown(void **state) {
    (void)state;
    reset_stubs();

    upstream_server_t s;
    memset(&s, 0, sizeof(s));
    strcpy(s.host, "dns.google");

    struct in_addr a;
    assert_int_equal(inet_pton(AF_INET, "8.8.8.8", &a), 1);
    g_iter_rc = 0;
    g_iter_addr = a.s_addr;

    assert_int_equal(upstream_bootstrap_try_stage3(&s, 1000, NULL), 0);
    assert_int_equal(s.stage.has_bootstrap_v4, 1);
    assert_int_equal(s.stage.bootstrap_addr_v4_be, a.s_addr);

    /* Immediate second attempt is cooldown-limited. */
    assert_int_equal(upstream_bootstrap_try_stage3(&s, 1000, NULL), -1);

    /* Force retry window and failure branch. */
    s.stage.iterative_last_attempt_ms = 0;
    g_iter_rc = -1;
    assert_int_equal(upstream_bootstrap_try_stage3(&s, 1000, NULL), -1);

    assert_int_equal(upstream_bootstrap_try_stage3(NULL, 1000, NULL), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_configure_paths),
        cmocka_unit_test(test_stage2_no_resolvers),
        cmocka_unit_test(test_stage2_success_and_ttl_clamp),
        cmocka_unit_test(test_stage1_hydrate_success),
        cmocka_unit_test(test_stage3_success_failure_and_cooldown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
