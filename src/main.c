#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "dns_server.h"
#include "logger.h"
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
        LOGF_ERROR("Failed to load configuration");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    LOGF_INFO("Loaded configuration from %s", config.config_path);
    LOGF_INFO("Starting DNS listener on %s:%d (UDP+TCP)", config.listen_addr, config.listen_port);

    proxy_server_t server;
    if (proxy_server_init(&server, &config, &g_stop) != 0) {
        LOGF_ERROR("Failed to initialize server");
        return 1;
    }

    if (config.metrics_enabled) {
        if (metrics_server_start(&server.metrics, &server.cache, &server.upstream, config.metrics_port) != 0) {
            LOGF_ERROR("Failed to start metrics server on port %d", config.metrics_port);
            proxy_server_destroy(&server);
            return 1;
        }
        LOGF_INFO("Metrics endpoint listening on 0.0.0.0:%d/metrics", config.metrics_port);
    }

    int rc = proxy_server_run(&server);

    metrics_server_stop();
    proxy_server_destroy(&server);

    if (rc != 0) {
        return 1;
    }

    return 0;
}
