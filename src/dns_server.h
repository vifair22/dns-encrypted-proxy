#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <signal.h>
#include <stdatomic.h>

#include "cache.h"
#include "config.h"
#include "upstream.h"
#include "upstream_dispatch.h"
#include "metrics.h"

typedef struct {
    proxy_config_t config;
    dns_cache_t cache;
    upstream_client_t upstream;
    upstream_facilitator_t upstream_facilitator;
    proxy_metrics_t metrics;
    volatile sig_atomic_t *stop_flag;
    atomic_int active_tcp_clients;
} proxy_server_t;

int proxy_server_init(proxy_server_t *server, const proxy_config_t *config, volatile sig_atomic_t *stop_flag);
void proxy_server_destroy(proxy_server_t *server);
int proxy_server_run(proxy_server_t *server);

#endif
