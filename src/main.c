#define _POSIX_C_SOURCE 200809L

#include "cache.h"
#include "config.h"
#include "dns_server.h"
#include "doh_client.h"
#include "metrics.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

int main(int argc, char **argv) {
    const char *config_path = NULL;
    if (argc > 1) {
        config_path = argv[1];
    }

    proxy_config_t config;
    if (config_load(&config, config_path) != 0) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }

    dns_cache_t cache;
    if (dns_cache_init(&cache, (size_t)config.cache_capacity) != 0) {
        fprintf(stderr, "Failed to initialize cache\n");
        return 1;
    }

    doh_client_t doh_client;
    if (doh_client_init(&doh_client, &config) != 0) {
        fprintf(stderr, "Failed to initialize DoH client\n");
        dns_cache_destroy(&cache);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    config_print(&config, stdout);
    fprintf(stdout, "Starting DNS listener on %s:%d (UDP+TCP)\n", config.listen_addr, config.listen_port);
    fflush(stdout);

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    server.config = config;
    server.cache = cache;
    server.doh_client = doh_client;
    server.stop_flag = &g_stop;
    metrics_init(&server.metrics);

    if (server.config.metrics_enabled && server.config.metrics_port > 0) {
        if (metrics_server_start(&server.metrics, server.config.metrics_port) != 0) {
            fprintf(stderr, "Failed to start metrics server on port %d\n", server.config.metrics_port);
            doh_client_destroy(&server.doh_client);
            dns_cache_destroy(&server.cache);
            return 1;
        }
        fprintf(stdout, "Metrics endpoint listening on 0.0.0.0:%d/metrics\n", server.config.metrics_port);
        fflush(stdout);
    }

    int rc = proxy_server_run(&server);

    metrics_server_stop();

    doh_client_destroy(&server.doh_client);
    dns_cache_destroy(&server.cache);

    if (rc != 0) {
        return 1;
    }

    return 0;
}
