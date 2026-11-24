#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "dns_server.h"
#include "logger.h"
#include "metrics.h"
#include "report.h"
#include "sd_notify.h"
#include "version.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;
/* Set once the upstream client exists; SIGHUP before then has nothing to
 * reconnect and is dropped. */
static upstream_client_t *volatile g_reconnect_target = NULL;

static void handle_signal(int sig) {
    (void)sig;
    static const char stopping[] = "STOPPING=1";
    sd_notify_send_signal_safe(stopping, sizeof(stopping) - 1);
    g_stop = 1;
}

/*
 * SIGHUP: drop and redial every pooled upstream connection. A WAN failover
 * daemon (or systemd ExecReload) sends it when the default route moves.
 * Only bumps an atomic generation; the dispatch allocator does the work.
 */
static void handle_reconnect_signal(int sig) {
    (void)sig;
    upstream_client_t *target = g_reconnect_target;
    if (target != NULL) {
        upstream_client_request_reconnect(target);
    }
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
    printf("\n");
    printf("Signals:\n");
    printf("  SIGTERM, SIGINT     Shut down cleanly.\n");
    printf("  SIGHUP              Drop and redial all pooled upstream connections\n");
    printf("                      (for a route change, e.g. WAN failover).\n");
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
    if (config_load(&config, config_path) != PROXY_OK) {
        LOGF_ERROR("Failed to load configuration: %s", proxy_error_message());
        return 1;
    }

    logger_set_level(config.log_level);

    /* Fatal on a bad NOTIFY_SOCKET: under Type=notify, carrying on would
     * only turn a clear error into a start timeout. */
    if (sd_notify_init() != PROXY_OK) {
        LOGF_ERROR("systemd notification setup failed: %s", proxy_error_message());
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Installed before the server exists so an early SIGHUP is ignored
     * rather than killing the process (SIGHUP's default action). */
    struct sigaction sa_hup;
    memset(&sa_hup, 0, sizeof(sa_hup));
    sa_hup.sa_handler = handle_reconnect_signal;
    sa_hup.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa_hup, NULL);

    LOGF_INFO("dns-encrypted-proxy %s starting", PROXY_VERSION_FULL);
    /* Fatal only when the socket cannot be created at all. A collector that
     * is not listening yet is normal: events are dropped until it is. */
    if (config.report_socket[0] != '\0') {
        if (report_open(config.report_socket) != PROXY_OK) {
            LOGF_ERROR("Failed to set up the report socket: %s", proxy_error_message());
            return 1;
        }
        LOGF_INFO("Sending query and upstream reports to %s", config.report_socket);
    }
    LOGF_INFO("Loaded configuration from %s", config.config_path);
    LOGF_INFO("Starting DNS listener on %s:%d (UDP+TCP)", config.listen_addr, config.listen_port);

    proxy_server_t server;
    if (proxy_server_init(&server, &config, &g_stop) != PROXY_OK) {
        LOGF_ERROR("Failed to initialize server: %s", proxy_error_message());
        report_close();
        return 1;
    }

    g_reconnect_target = &server.upstream;

    if (config.metrics_enabled) {
        if (metrics_server_start(&server.metrics, &server.cache, &server.upstream, &server.upstream_facilitator, config.metrics_addr, config.metrics_port) != PROXY_OK) {
            LOGF_ERROR("Failed to start metrics server on %s:%d: %s", config.metrics_addr, config.metrics_port, proxy_error_message());
            g_reconnect_target = NULL;
            proxy_server_destroy(&server);
            report_close();
            return 1;
        }
        LOGF_INFO("Metrics endpoint listening on %s:%d/metrics (health: /healthz, ready: /readyz)", config.metrics_addr, config.metrics_port);
    }

    proxy_status_t rc = proxy_server_run(&server);

    g_reconnect_target = NULL;
    metrics_server_stop();
    proxy_server_destroy(&server);
    report_close();
    sd_notify_close();

    if (rc != PROXY_OK) {
        LOGF_ERROR("Proxy server runtime error: %s", proxy_error_message());
        return 1;
    }

    return 0;
}
