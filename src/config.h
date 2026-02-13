#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>

#define MAX_UPSTREAMS 8
#define MAX_URL_LEN 512

typedef struct {
    char listen_addr[64];
    int listen_port;
    int upstream_timeout_ms;
    int doh_pool_size;
    int cache_capacity;
    char upstream_urls[MAX_UPSTREAMS][MAX_URL_LEN];
    int upstream_count;
    char config_path[256];
    int tcp_idle_timeout_ms;
    int tcp_max_clients;
    int tcp_max_queries_per_conn;
} proxy_config_t;

int config_load(proxy_config_t *config, const char *explicit_path);
void config_print(const proxy_config_t *config, FILE *out);

#endif
