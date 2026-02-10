#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <signal.h>

#include "cache.h"
#include "config.h"
#include "doh_client.h"

typedef struct {
    proxy_config_t config;
    dns_cache_t cache;
    doh_client_t doh_client;
    volatile sig_atomic_t *stop_flag;
} proxy_server_t;

int proxy_server_run(proxy_server_t *server);

#endif
