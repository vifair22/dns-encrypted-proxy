#ifndef UPSTREAM_BOOTSTRAP_H
#define UPSTREAM_BOOTSTRAP_H

#include "config.h"
#include "upstream.h"

int upstream_bootstrap_apply_from_config(
    upstream_client_t *client,
    const proxy_config_t *config,
    int *applied_out,
    int *unmatched_out);

int upstream_bootstrap_try_stage3(upstream_server_t *server, int timeout_ms);

#endif
