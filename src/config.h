#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdint.h>

#include "errors.h"

#define MAX_UPSTREAMS 8
#define MAX_URL_LEN 512
#define MAX_HOSTS_A_OVERRIDES 64
#define MAX_BOOTSTRAP_RESOLVERS 8

typedef struct {
    char name[256];
    uint32_t addr_v4_be;
    uint32_t name_hash;
    int in_use;
} hosts_a_override_t;

typedef struct {
    char listen_addr[64];
    int listen_port;
    int upstream_timeout_ms;
    int upstream_pool_size;
    int max_inflight_doh;
    int max_inflight_dot;
    int max_inflight_doq;
    int cache_capacity;
    char upstream_urls[MAX_UPSTREAMS][MAX_URL_LEN];
    int upstream_count;
    char config_path[256];
    int tcp_idle_timeout_ms;
    int tcp_max_clients;
    int tcp_max_queries_per_conn;
    int metrics_enabled;
    int metrics_port;
    char log_level[16];
    int bootstrap_resolver_count;
    char bootstrap_resolvers[MAX_BOOTSTRAP_RESOLVERS][64];
    hosts_a_override_t hosts_a_overrides[MAX_HOSTS_A_OVERRIDES];
    int hosts_a_override_count;
} proxy_config_t;

proxy_status_t config_load(proxy_config_t *config, const char *explicit_path);
void config_print(const proxy_config_t *config, FILE *out);
int config_lookup_hosts_a(const proxy_config_t *config, const char *name, uint32_t *addr_v4_be_out);

#endif
