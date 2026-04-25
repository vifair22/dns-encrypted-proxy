#ifndef UPSTREAM_DOQ_H
#define UPSTREAM_DOQ_H

#include "errors.h"
#include "upstream.h"

#include <stddef.h>
#include <stdint.h>

proxy_status_t upstream_doq_client_init(upstream_doq_client_t **client_out, const upstream_config_t *config);
void upstream_doq_client_destroy(upstream_doq_client_t *client);
int upstream_doq_resolve(
    upstream_doq_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_doq_client_get_pool_stats(
    upstream_doq_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out);

#endif /* UPSTREAM_DOQ_H */
