#ifndef DOH_CLIENT_H
#define DOH_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include <curl/curl.h>
#include <pthread.h>

#include "config.h"

typedef struct {
    char urls[MAX_UPSTREAMS][MAX_URL_LEN];
    int url_count;
    int timeout_ms;
    pthread_mutex_t rr_mutex;
    uint64_t next_index;
    CURL **pool_handles;
    int *pool_in_use;
    int pool_size;
    pthread_mutex_t pool_mutex;
    pthread_cond_t pool_cond;
} doh_client_t;

int doh_client_init(doh_client_t *client, const proxy_config_t *config);
void doh_client_destroy(doh_client_t *client);

int doh_client_resolve(
    doh_client_t *client,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out,
    const char **used_url_out);

#endif
