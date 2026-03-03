#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <string.h>

#include "config.h"
#include "upstream.h"

static int g_apply_hits = 0;
static int g_iter_rc = -1;
static uint32_t g_iter_addr = 0;

int upstream_client_set_bootstrap_ipv4(upstream_client_t *client, const char *host, uint32_t addr_v4_be) {
    (void)client;
    (void)addr_v4_be;
    if (host != NULL && strcmp(host, "matched.example") == 0) {
        g_apply_hits++;
        return 1;
    }
    return 0;
}

int iterative_resolve_a(const char *hostname, int timeout_ms, uint32_t *addr_v4_be_out) {
    (void)hostname;
    (void)timeout_ms;
    if (g_iter_rc == 0 && addr_v4_be_out != NULL) {
        *addr_v4_be_out = g_iter_addr;
    }
    return g_iter_rc;
}

#include "../../src/upstream_bootstrap.c"

static void reset_stubs(void) {
    g_apply_hits = 0;
    g_iter_rc = -1;
    g_iter_addr = 0;
}

static void test_apply_from_config_paths(void **state) {
    (void)state;
    reset_stubs();

    upstream_client_t client;
    memset(&client, 0, sizeof(client));
    proxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.upstream_bootstrap_enabled = 1;
    cfg.upstream_bootstrap_a_count = 2;
    cfg.upstream_bootstrap_a[0].in_use = 1;
    strcpy(cfg.upstream_bootstrap_a[0].name, "matched.example");
    cfg.upstream_bootstrap_a[1].in_use = 1;
    strcpy(cfg.upstream_bootstrap_a[1].name, "miss.example");

    int applied = 0;
    int unmatched = 0;
    assert_int_equal(upstream_bootstrap_apply_from_config(&client, &cfg, &applied, &unmatched), 0);
    assert_int_equal(applied, 1);
    assert_int_equal(unmatched, 1);
    assert_int_equal(g_apply_hits, 1);

    cfg.upstream_bootstrap_enabled = 0;
    applied = 0;
    unmatched = 0;
    assert_int_equal(upstream_bootstrap_apply_from_config(&client, &cfg, &applied, &unmatched), 0);
    assert_int_equal(applied, 0);
    assert_int_equal(unmatched, 2);

    assert_int_equal(upstream_bootstrap_apply_from_config(NULL, &cfg, &applied, &unmatched), -1);
    assert_int_equal(upstream_bootstrap_apply_from_config(&client, NULL, &applied, &unmatched), -1);
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

    assert_int_equal(upstream_bootstrap_try_stage3(&s, 1000), 0);
    assert_int_equal(s.has_bootstrap_v4, 1);
    assert_int_equal(s.bootstrap_addr_v4_be, a.s_addr);

    /* Immediate second attempt is cooldown-limited. */
    assert_int_equal(upstream_bootstrap_try_stage3(&s, 1000), -1);

    /* Force retry window and failure branch. */
    s.iterative_last_attempt_ms = 0;
    g_iter_rc = -1;
    assert_int_equal(upstream_bootstrap_try_stage3(&s, 1000), -1);

    assert_int_equal(upstream_bootstrap_try_stage3(NULL, 1000), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_apply_from_config_paths),
        cmocka_unit_test(test_stage3_success_failure_and_cooldown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
