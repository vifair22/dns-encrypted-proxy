#define _POSIX_C_SOURCE 200809L

#include "upstream.h"
#include "upstream_doq.h"
#include "dns_message.h"

#include <stdlib.h>
#include <string.h>

#define DOQ_MAX_DNS_MESSAGE_SIZE 65535u

/*
 * DoQ implementation scaffold.
 *
 * This keeps protocol plumbing and observability paths live while QUIC
 * transport integration is implemented. Current behavior intentionally fails
 * resolve attempts for DoQ upstreams instead of silently degrading.
 */

struct upstream_doq_client {
    int pool_size;
};

int upstream_doq_ngtcp2_resolve(
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);

int upstream_doq_client_init(upstream_doq_client_t **client_out, const upstream_config_t *config) {
    if (client_out == NULL || config == NULL) {
        return -1;
    }

    upstream_doq_client_t *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return -1;
    }

    client->pool_size = config->pool_size > 0 ? config->pool_size : 1;
    *client_out = client;
    return 0;
}

void upstream_doq_client_destroy(upstream_doq_client_t *client) {
    free(client);
}

int upstream_doq_resolve(
    upstream_doq_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (client == NULL || server == NULL || query == NULL || query_len == 0 ||
        response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    if (server->type != UPSTREAM_TYPE_DOQ) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    if (query_len > DOQ_MAX_DNS_MESSAGE_SIZE) {
        return -1;
    }

    int result = upstream_doq_ngtcp2_resolve(
        server,
        timeout_ms,
        query,
        query_len,
        response_out,
        response_len_out);

    if (result != 0 || *response_out == NULL || *response_len_out == 0) {
        free(*response_out);
        *response_out = NULL;
        *response_len_out = 0;
        return -1;
    }

    if (dns_validate_response_for_query(query, query_len, *response_out, *response_len_out) != 0) {
        free(*response_out);
        *response_out = NULL;
        *response_len_out = 0;
        return -1;
    }

    return 0;
}

int upstream_doq_client_get_pool_stats(
    upstream_doq_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out) {
    if (capacity_out != NULL) {
        *capacity_out = 0;
    }
    if (in_use_out != NULL) {
        *in_use_out = 0;
    }
    if (alive_out != NULL) {
        *alive_out = 0;
    }

    if (client == NULL) {
        return -1;
    }

    if (capacity_out != NULL) {
        *capacity_out = client->pool_size;
    }
    return 0;
}
