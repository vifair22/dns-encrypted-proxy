#ifndef UPSTREAM_DOH_H
#define UPSTREAM_DOH_H

#include "upstream.h"

#include <stddef.h>
#include <stdint.h>

int upstream_doh_client_init(upstream_doh_client_t **client_out, const upstream_config_t *config);
void upstream_doh_client_destroy(upstream_doh_client_t *client);
int upstream_doh_resolve(
    upstream_doh_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_doh_client_get_pool_stats(
    upstream_doh_client_t *client,
    int *capacity_out,
    int *in_use_out,
    uint64_t *http3_total_out,
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out);

#endif /* UPSTREAM_DOH_H */
