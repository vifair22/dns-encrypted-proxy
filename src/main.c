#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "dns_server.h"
#include "logger.h"
#include "metrics.h"
#include "version.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void print_version(void) {
    /* stdout: tools that scrape --version output expect normal-channel data */
    printf("dns-encrypted-proxy %s\n", PROXY_VERSION_FULL);
}

static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS] [CONFIG_PATH]\n", progname);
    printf("\n");
    printf("Encrypted-DNS forward proxy: serves classic DNS over UDP/TCP and\n");
    printf("forwards to DoH/DoT/DoQ upstreams.\n");
    printf("\n");
    printf("Positional:\n");
    printf("  CONFIG_PATH         Path to a TOML/INI config file. If omitted,\n");
    printf("                      the value of $DNS_ENCRYPTED_PROXY_CONFIG is used,\n");
    printf("                      falling back to ./dns-encrypted-proxy.conf.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help          Show this help and exit.\n");
    printf("  -v, --version       Print version and exit.\n");
}

int main(int argc, char **argv) {
    const char *config_path = NULL;
    if (argc > 1) {
        const char *arg = argv[1];
        if (strcmp(arg, "--version") == 0 || strcmp(arg, "-v") == 0) {
            print_version();
            return 0;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        config_path = arg;
    }

    proxy_config_t config;
    if (config_load(&config, config_path) != 0) {
        LOGF_ERROR("Failed to load configuration");
        return 1;
    }

    logger_set_level(config.log_level);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    LOGF_INFO("dns-encrypted-proxy %s starting", PROXY_VERSION_FULL);
    LOGF_INFO("Loaded configuration from %s", config.config_path);
    LOGF_INFO("Starting DNS listener on %s:%d (UDP+TCP)", config.listen_addr, config.listen_port);

    proxy_server_t server;
    if (proxy_server_init(&server, &config, &g_stop) != 0) {
        LOGF_ERROR("Failed to initialize server");
        return 1;
    }

    if (config.metrics_enabled) {
        if (metrics_server_start(&server.metrics, &server.cache, &server.upstream, &server.upstream_facilitator, config.metrics_port) != 0) {
            LOGF_ERROR("Failed to start metrics server on port %d", config.metrics_port);
            proxy_server_destroy(&server);
            return 1;
        }
        LOGF_INFO("Metrics endpoint listening on 0.0.0.0:%d/metrics (health: /healthz, ready: /readyz)", config.metrics_port);
    }

    int rc = proxy_server_run(&server);

    metrics_server_stop();
    proxy_server_destroy(&server);

    if (rc != 0) {
        return 1;
    }

    return 0;
}
