#ifndef UPSTREAM_DOT_H
#define UPSTREAM_DOT_H

#include "errors.h"
#include "upstream.h"

#include <stddef.h>
#include <stdint.h>

proxy_status_t upstream_dot_client_init(upstream_dot_client_t **client_out, const upstream_config_t *config);
void upstream_dot_client_destroy(upstream_dot_client_t *client);
int upstream_dot_resolve(
    upstream_dot_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_dot_client_get_pool_stats(
    upstream_dot_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out);

#endif /* UPSTREAM_DOT_H */
