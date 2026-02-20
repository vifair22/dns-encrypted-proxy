#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "dns_server.h"
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

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    config_print(&config, stdout);
    fprintf(stdout, "Starting DNS listener on %s:%d (UDP+TCP)\n", config.listen_addr, config.listen_port);
    fflush(stdout);

    proxy_server_t server;
    if (proxy_server_init(&server, &config, &g_stop) != 0) {
        fprintf(stderr, "Failed to initialize server\n");
        return 1;
    }

    if (config.metrics_enabled && config.metrics_port > 0) {
        if (metrics_server_start(&server.metrics, config.metrics_port) != 0) {
            fprintf(stderr, "Failed to start metrics server on port %d\n", config.metrics_port);
            proxy_server_destroy(&server);
            return 1;
        }
        fprintf(stdout, "Metrics endpoint listening on 0.0.0.0:%d/metrics\n", config.metrics_port);
        fflush(stdout);
    }

    int rc = proxy_server_run(&server);

    metrics_server_stop();
    proxy_server_destroy(&server);

    if (rc != 0) {
        return 1;
    }

    return 0;
}
