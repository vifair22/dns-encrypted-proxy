#ifndef UPSTREAM_BOOTSTRAP_H
#define UPSTREAM_BOOTSTRAP_H

#include "config.h"
#include "upstream.h"

#define UPSTREAM_STAGE3_RETRY_COOLDOWN_MS 30000ULL

typedef enum {
    UPSTREAM_STAGE1_CACHE_MISS = 0,
    UPSTREAM_STAGE1_CACHE_HIT = 1,
    UPSTREAM_STAGE1_CACHE_REFRESHED = 2,
} upstream_stage1_cache_result_t;

int upstream_bootstrap_configure(upstream_client_t *client, const proxy_config_t *config);

int upstream_bootstrap_try_stage3(upstream_server_t *server, int timeout_ms, const char **reason_out);
int upstream_bootstrap_try_stage2(upstream_client_t *client, upstream_server_t *server, int timeout_ms, const char **reason_out);
upstream_stage1_cache_result_t upstream_bootstrap_stage1_prepare(upstream_server_t *server);
int upstream_bootstrap_stage1_hydrate(upstream_client_t *client, upstream_server_t *server, int timeout_ms);
void upstream_bootstrap_stage1_invalidate(upstream_server_t *server);

#endif
