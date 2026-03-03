#define _POSIX_C_SOURCE 200809L

#include "upstream_bootstrap.h"

#include "iterative_resolver.h"

#include <time.h>

#define STAGE3_ITERATIVE_RETRY_COOLDOWN_MS 30000ULL

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int upstream_bootstrap_apply_from_config(
    upstream_client_t *client,
    const proxy_config_t *config,
    int *applied_out,
    int *unmatched_out) {
    if (client == NULL || config == NULL) {
        return -1;
    }

    int applied = 0;
    if (config->upstream_bootstrap_enabled) {
        for (int i = 0; i < MAX_UPSTREAM_BOOTSTRAP_A; i++) {
            const upstream_bootstrap_a_t *entry = &config->upstream_bootstrap_a[i];
            if (!entry->in_use) {
                continue;
            }
            applied += upstream_client_set_bootstrap_ipv4(client, entry->name, entry->addr_v4_be);
        }
    }

    int unmatched = config->upstream_bootstrap_a_count - applied;
    if (unmatched < 0) {
        unmatched = 0;
    }

    if (applied_out != NULL) {
        *applied_out = applied;
    }
    if (unmatched_out != NULL) {
        *unmatched_out = unmatched;
    }

    return 0;
}

int upstream_bootstrap_try_stage3(upstream_server_t *server, int timeout_ms) {
    if (server == NULL) {
        return -1;
    }

    uint64_t now = now_ms();
    if (server->iterative_last_attempt_ms != 0 &&
        now - server->iterative_last_attempt_ms < STAGE3_ITERATIVE_RETRY_COOLDOWN_MS) {
        return -1;
    }
    server->iterative_last_attempt_ms = now;

    uint32_t addr_be = 0;
    if (iterative_resolve_a(server->host, timeout_ms, &addr_be) != 0) {
        return -1;
    }

    server->bootstrap_addr_v4_be = addr_be;
    server->has_bootstrap_v4 = 1;
    return 0;
}
