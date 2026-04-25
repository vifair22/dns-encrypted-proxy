#ifndef UPSTREAM_DOQ_NGTCP2_H
#define UPSTREAM_DOQ_NGTCP2_H

#include "upstream.h"

#include <stddef.h>
#include <stdint.h>

int upstream_doq_ngtcp2_resolve(
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);

#endif /* UPSTREAM_DOQ_NGTCP2_H */
