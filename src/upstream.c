#define _POSIX_C_SOURCE 200809L

#include "upstream.h"
#include "upstream_bootstrap.h"
#include "logger.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>

/* Forward declarations for protocol-specific functions */
#if UPSTREAM_DOH_ENABLED
int upstream_doh_client_init(upstream_doh_client_t **client, const upstream_config_t *config);
void upstream_doh_client_destroy(upstream_doh_client_t *client);
int upstream_doh_resolve(
    upstream_doh_client_t *client,
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_doh_client_get_pool_stats(
    upstream_doh_client_t *client,
    int *capacity_out,
    int *in_use_out,
    uint64_t *http3_total_out,
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out);
#endif

#if UPSTREAM_DOT_ENABLED
int upstream_dot_client_init(upstream_dot_client_t **client, const upstream_config_t *config);
void upstream_dot_client_destroy(upstream_dot_client_t *client);
int upstream_dot_resolve(
    upstream_dot_client_t *client,
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_dot_client_get_pool_stats(
    upstream_dot_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out);
#endif

#if UPSTREAM_DOQ_ENABLED
int upstream_doq_client_init(upstream_doq_client_t **client, const upstream_config_t *config);
void upstream_doq_client_destroy(upstream_doq_client_t *client);
int upstream_doq_resolve(
    upstream_doq_client_t *client,
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_doq_client_get_pool_stats(
    upstream_doq_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out);
#endif

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static const char *upstream_type_name(upstream_type_t type) {
    switch (type) {
        case UPSTREAM_TYPE_DOH:
            return "doh";
        case UPSTREAM_TYPE_DOT:
            return "dot";
        case UPSTREAM_TYPE_DOQ:
            return "doq";
        default:
            return "unknown";
    }
}

#if UPSTREAM_DOT_ENABLED || UPSTREAM_DOQ_ENABLED
static int parse_port_strict(const char *port_text, int *port_out) {
    if (port_text == NULL || port_out == NULL || *port_text == '\0') {
        return -1;
    }

    errno = 0;
    char *endptr = NULL;
    long value = strtol(port_text, &endptr, 10);
    if (errno != 0 || endptr == NULL || *endptr != '\0') {
        return -1;
    }
    if (value <= 0 || value > 65535) {
        return -1;
    }

    *port_out = (int)value;
    return 0;
}

static int parse_authority_host_port(
    const char *authority,
    char *host_out,
    size_t host_out_len,
    int default_port,
    int *port_out) {
    if (authority == NULL || host_out == NULL || host_out_len == 0 || port_out == NULL) {
        return -1;
    }
    if (*authority == '\0') {
        return -1;
    }

    /* DoT/DoQ authority is host[:port] only; paths/fragments are invalid. */
    if (strpbrk(authority, "/?#") != NULL) {
        return -1;
    }

    const char *host_start = authority;
    const char *host_end = NULL;
    const char *port_text = NULL;

    if (authority[0] == '[') {
        const char *close_bracket = strchr(authority + 1, ']');
        if (close_bracket == NULL) {
            return -1;
        }
        host_start = authority + 1;
        host_end = close_bracket;
        if (close_bracket[1] == ':') {
            port_text = close_bracket + 2;
        } else if (close_bracket[1] != '\0') {
            return -1;
        }
    } else {
        const char *colon = strchr(authority, ':');
        if (colon != NULL) {
            if (strchr(colon + 1, ':') != NULL) {
                return -1;
            }
            host_end = colon;
            port_text = colon + 1;
        } else {
            host_end = authority + strlen(authority);
        }
    }

    size_t host_len = (size_t)(host_end - host_start);
    if (host_len == 0 || host_len >= host_out_len) {
        return -1;
    }

    memcpy(host_out, host_start, host_len);
    host_out[host_len] = '\0';
    *port_out = default_port;

    if (port_text != NULL && parse_port_strict(port_text, port_out) != 0) {
        return -1;
    }

    return 0;
}
#endif

int upstream_parse_url(const char *url, upstream_server_t *server_out) {
    if (url == NULL || server_out == NULL) {
        return -1;
    }

    memset(server_out, 0, sizeof(*server_out));
    
    /*
     * URL parsing here is intentionally strict/minimal and only accepts the
     * schemes we explicitly support. This keeps config failures obvious and
     * avoids silently treating unknown schemes as valid upstreams.
     */
    /* Check for https:// (DoH) */
#if UPSTREAM_DOH_ENABLED
    if (strncmp(url, "https://", 8) == 0) {
        server_out->type = UPSTREAM_TYPE_DOH;
        strncpy(server_out->url, url, UPSTREAM_MAX_URL_LEN - 1);
        server_out->url[UPSTREAM_MAX_URL_LEN - 1] = '\0';
        
        /* Parse host from URL */
        const char *host_start = url + 8;
        const char *host_end = host_start;
        while (*host_end != '\0' && *host_end != '/' && *host_end != ':') {
            host_end++;
        }
        
        size_t host_len = (size_t)(host_end - host_start);
        if (host_len == 0 || host_len >= sizeof(server_out->host)) {
            return -1;
        }
        
        memcpy(server_out->host, host_start, host_len);
        server_out->host[host_len] = '\0';
        server_out->port = 443;  /* Default HTTPS port */
        
        /* Parse port if specified */
        if (*host_end == ':') {
            server_out->port = atoi(host_end + 1);
            if (server_out->port <= 0 || server_out->port > 65535) {
                return -1;
            }
        }
        
        server_out->health.healthy = 1;
        return 0;
    }
#endif
    
    /* Check for tls:// (DoT) */
#if UPSTREAM_DOT_ENABLED
    if (strncmp(url, "tls://", 6) == 0) {
        server_out->type = UPSTREAM_TYPE_DOT;
        strncpy(server_out->url, url, UPSTREAM_MAX_URL_LEN - 1);
        server_out->url[UPSTREAM_MAX_URL_LEN - 1] = '\0';
        if (parse_authority_host_port(
                url + 6,
                server_out->host,
                sizeof(server_out->host),
                853,
                &server_out->port)
            != 0) {
            return -1;
        }
        
        server_out->health.healthy = 1;
        return 0;
    }
#endif

#if UPSTREAM_DOQ_ENABLED
    if (strncmp(url, "quic://", 7) == 0) {
        const char *host_start = url + 7;
        server_out->type = UPSTREAM_TYPE_DOQ;
        strncpy(server_out->url, url, UPSTREAM_MAX_URL_LEN - 1);
        server_out->url[UPSTREAM_MAX_URL_LEN - 1] = '\0';
        if (parse_authority_host_port(
                host_start,
                server_out->host,
                sizeof(server_out->host),
                853,
                &server_out->port)
            != 0) {
            return -1;
        }

        server_out->health.healthy = 1;
        return 0;
    }
#endif
    
    /* Unknown scheme */
    return -1;
}

int upstream_server_should_skip(const upstream_server_t *server, const upstream_config_t *config) {
    if (server == NULL || config == NULL) {
        return 1;
    }
    
    if (server->health.healthy) {
        return 0;
    }
    
    /* Skip recently-failed upstreams for a bit so we don't thrash them. */
    /* Check if backoff period has elapsed */
    uint64_t now = now_ms();
    uint64_t elapsed = now - server->health.last_failure_time;
    
    if (elapsed >= (uint64_t)config->unhealthy_backoff_ms) {
        /*
         * Retry probe after backoff even for unhealthy servers so they can
         * re-enter service automatically without operator intervention.
         */
        return 0;
    }
    
    return 1;
}

void upstream_server_record_success(upstream_server_t *server) {
    if (server == NULL) {
        return;
    }

    int was_unhealthy = !server->health.healthy;
    
    server->health.healthy = 1;
    server->health.consecutive_failures = 0;
    server->health.last_success_time = now_ms();
    server->health.total_queries++;

    if (was_unhealthy) {
        LOGF_INFO(
            "Upstream recovered: host=%s type=%s total_failures=%llu",
            server->host,
            upstream_type_name(server->type),
            (unsigned long long)server->health.total_failures);
    }
}

void upstream_server_record_failure(upstream_server_t *server, const upstream_config_t *config) {
    if (server == NULL || config == NULL) {
        return;
    }

    int was_healthy = server->health.healthy;
    
    server->health.consecutive_failures++;
    server->health.last_failure_time = now_ms();
    server->health.total_queries++;
    server->health.total_failures++;
    
    if (server->health.consecutive_failures >= (uint32_t)config->max_failures_before_unhealthy) {
        server->health.healthy = 0;
    }

    if (was_healthy && !server->health.healthy) {
        LOGF_WARN(
            "Upstream marked unhealthy: host=%s type=%s consecutive_failures=%u backoff_ms=%d",
            server->host,
            upstream_type_name(server->type),
            server->health.consecutive_failures,
            config->unhealthy_backoff_ms);
    }
}

int upstream_client_init(
    upstream_client_t *client,
    const char *urls[],
    int url_count,
    const upstream_config_t *config) {
    
    if (client == NULL || urls == NULL || url_count <= 0 || config == NULL) {
        return -1;
    }
    
    if (url_count > UPSTREAM_MAX_SERVERS) {
        url_count = UPSTREAM_MAX_SERVERS;
    }
    
    memset(client, 0, sizeof(*client));
    client->config = *config;
    
    /* Set defaults for policy settings */
    if (client->config.max_failures_before_unhealthy <= 0) {
        client->config.max_failures_before_unhealthy = 3;
    }
    if (client->config.unhealthy_backoff_ms <= 0) {
        client->config.unhealthy_backoff_ms = 10000;  /* 10 seconds */
    }
    if (client->config.iterative_bootstrap_enabled != 0) {
        client->config.iterative_bootstrap_enabled = 1;
    }
    
    /*
     * Parse all configured URLs up front so runtime resolution path only
     * handles transport work and health policy, not config validation.
     */
    /* Parse all URLs */
    for (int i = 0; i < url_count; i++) {
        if (upstream_parse_url(urls[i], &client->servers[client->server_count]) == 0) {
            client->server_count++;
        }
    }
    
    if (client->server_count == 0) {
        return -1;
    }
    
    if (pthread_mutex_init(&client->rr_mutex, NULL) != 0) {
        return -1;
    }
    
    /*
     * Lazily initialize DoH/DoT/DoQ clients so startup remains lightweight when a
     * protocol is configured but never selected on the active path.
     */
    /* Initialize protocol-specific clients lazily on first use */
    client->doh_client = NULL;
    client->dot_client = NULL;
    client->doq_client = NULL;
    
    return 0;
}

void upstream_client_destroy(upstream_client_t *client) {
    if (client == NULL) {
        return;
    }
    
#if UPSTREAM_DOH_ENABLED
    if (client->doh_client != NULL) {
        upstream_doh_client_destroy(client->doh_client);
    }
#endif

#if UPSTREAM_DOT_ENABLED
    if (client->dot_client != NULL) {
        upstream_dot_client_destroy(client->dot_client);
    }
#endif

#if UPSTREAM_DOQ_ENABLED
    if (client->doq_client != NULL) {
        upstream_doq_client_destroy(client->doq_client);
    }
#endif
    
    pthread_mutex_destroy(&client->rr_mutex);
    memset(client, 0, sizeof(*client));
}

#if UPSTREAM_DOH_ENABLED
static int ensure_doh_client(upstream_client_t *client) {
    if (client->doh_client != NULL) {
        return 0;
    }
    return upstream_doh_client_init(&client->doh_client, &client->config);
}
#endif

#if UPSTREAM_DOT_ENABLED
static int ensure_dot_client(upstream_client_t *client) {
    if (client->dot_client != NULL) {
        return 0;
    }
    return upstream_dot_client_init(&client->dot_client, &client->config);
}
#endif

#if UPSTREAM_DOQ_ENABLED
static int ensure_doq_client(upstream_client_t *client) {
    if (client->doq_client != NULL) {
        return 0;
    }
    return upstream_doq_client_init(&client->doq_client, &client->config);
}
#endif

static int resolve_with_server(
    upstream_client_t *client,
    upstream_server_t *server,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    
    int result = -1;
    
    /* Central protocol dispatch keeps upstream selection policy transport-agnostic. */
    switch (server->type) {
        case UPSTREAM_TYPE_DOH:
#if UPSTREAM_DOH_ENABLED
            if (ensure_doh_client(client) != 0) {
                return -1;
            }
            result = upstream_doh_resolve(
                client->doh_client,
                server,
                client->config.timeout_ms,
                query, query_len,
                response_out, response_len_out);
            break;
#else
            return -1;
#endif
            
        case UPSTREAM_TYPE_DOT:
#if UPSTREAM_DOT_ENABLED
            if (ensure_dot_client(client) != 0) {
                return -1;
            }
            result = upstream_dot_resolve(
                client->dot_client,
                server,
                client->config.timeout_ms,
                query, query_len,
                response_out, response_len_out);
            break;
#else
            return -1;
#endif

        case UPSTREAM_TYPE_DOQ:
#if UPSTREAM_DOQ_ENABLED
            if (ensure_doq_client(client) != 0) {
                return -1;
            }
            result = upstream_doq_resolve(
                client->doq_client,
                server,
                client->config.timeout_ms,
                query,
                query_len,
                response_out,
                response_len_out);
            break;
#else
            return -1;
#endif
    }
    
    return result;
}

int upstream_resolve(
    upstream_client_t *client,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    
    if (client == NULL || query == NULL || query_len == 0 ||
        response_out == NULL || response_len_out == NULL) {
        return -1;
    }
    
    *response_out = NULL;
    *response_len_out = 0;
    
    /*
     * Take one RR snapshot per query so all retry attempts for that query use
     * a stable ordering, while subsequent queries still rotate fairly.
     */
    /* Get round-robin starting index */
    pthread_mutex_lock(&client->rr_mutex);
    uint64_t start = client->next_index;
    client->next_index++;
    pthread_mutex_unlock(&client->rr_mutex);
    
    /*
     * Pass 1 = normal path. Pass 2 = last-chance probe of unhealthy servers.
     * Keeps normal latency low but still lets bad servers recover.
     */
    /* Try each server in order, starting from round-robin index */
    for (int attempt = 0; attempt < client->server_count; attempt++) {
        int idx = (int)((start + (uint64_t)attempt) % (uint64_t)client->server_count);
        upstream_server_t *server = &client->servers[idx];
        
        /* Skip unhealthy servers unless backoff has elapsed */
        if (upstream_server_should_skip(server, &client->config)) {
            continue;
        }
        
        uint8_t *response = NULL;
        size_t response_len = 0;

        /* Stage 1 first on purpose: local DNS tracks provider IP changes. */
        LOGF_INFO("Upstream connect stage1 local resolver: host=%s type=%s", server->host, upstream_type_name(server->type));
        
        if (resolve_with_server(client, server, query, query_len, &response, &response_len) == 0) {
            upstream_server_record_success(server);
            *response_out = response;
            *response_len_out = response_len;
            return 0;
        }

        /* Keep this per-attempt so failover behavior is visible in prod logs. */
        LOGF_WARN("Upstream failed: host=%s type=%s", server->host, upstream_type_name(server->type));

        if (client->config.iterative_bootstrap_enabled) {
            if (server->has_bootstrap_v4) {
                LOGF_WARN("Upstream fallback stage3 iterative bootstrap: host=%s after stage2 bootstrap failure", server->host);
            } else {
                LOGF_WARN("Upstream fallback stage3 iterative bootstrap: host=%s stage2 bootstrap unavailable/disabled", server->host);
            }

            if (upstream_bootstrap_try_stage3(server, client->config.timeout_ms) == 0) {
                LOGF_INFO("Upstream stage3 iterative bootstrap resolved host=%s", server->host);
                if (resolve_with_server(client, server, query, query_len, &response, &response_len) == 0) {
                    upstream_server_record_success(server);
                    *response_out = response;
                    *response_len_out = response_len;
                    return 0;
                }
                LOGF_WARN("Upstream stage3 iterative bootstrap retry failed: host=%s", server->host);
            } else {
                LOGF_WARN("Upstream stage3 iterative bootstrap failed: host=%s", server->host);
            }
        }

        upstream_server_record_failure(server, &client->config);
    }
    
    /*
     * Pass 2 (last resort): probe unhealthy servers if healthy set failed.
     * This helps recover from stale health state when all primaries degraded.
     */
    /* All servers failed - try unhealthy servers as last resort */
    for (int attempt = 0; attempt < client->server_count; attempt++) {
        int idx = (int)((start + (uint64_t)attempt) % (uint64_t)client->server_count);
        upstream_server_t *server = &client->servers[idx];
        
        if (server->health.healthy) {
            continue;  /* Already tried */
        }
        
        uint8_t *response = NULL;
        size_t response_len = 0;

        /*
         * Pass 2 is a bounded "last chance" probe for currently unhealthy
         * entries. This avoids permanent brownout after stale health state while
         * keeping normal success path in pass 1 fast.
         */
        LOGF_INFO("Upstream connect retry unhealthy: host=%s type=%s", server->host, upstream_type_name(server->type));
        
        if (resolve_with_server(client, server, query, query_len, &response, &response_len) == 0) {
            upstream_server_record_success(server);
            *response_out = response;
            *response_len_out = response_len;
            return 0;
        }

        LOGF_WARN("Upstream unhealthy retry failed: host=%s type=%s", server->host, upstream_type_name(server->type));

        if (client->config.iterative_bootstrap_enabled) {
            if (server->has_bootstrap_v4) {
                LOGF_WARN("Upstream fallback stage3 iterative bootstrap: host=%s after stage2 bootstrap failure", server->host);
            } else {
                LOGF_WARN("Upstream fallback stage3 iterative bootstrap: host=%s stage2 bootstrap unavailable/disabled", server->host);
            }

            if (upstream_bootstrap_try_stage3(server, client->config.timeout_ms) == 0) {
                LOGF_INFO("Upstream stage3 iterative bootstrap resolved host=%s", server->host);
                if (resolve_with_server(client, server, query, query_len, &response, &response_len) == 0) {
                    upstream_server_record_success(server);
                    *response_out = response;
                    *response_len_out = response_len;
                    return 0;
                }
                LOGF_WARN("Upstream stage3 iterative bootstrap retry failed: host=%s", server->host);
            } else {
                LOGF_WARN("Upstream stage3 iterative bootstrap failed: host=%s", server->host);
            }
        }

        upstream_server_record_failure(server, &client->config);
    }
    
    return -1;
}

int upstream_client_set_bootstrap_ipv4(upstream_client_t *client, const char *host, uint32_t addr_v4_be) {
    if (client == NULL || host == NULL || *host == '\0') {
        return 0;
    }

    int applied = 0;
    for (int i = 0; i < client->server_count; i++) {
        upstream_server_t *server = &client->servers[i];
        if (strcasecmp(server->host, host) == 0) {
            server->bootstrap_addr_v4_be = addr_v4_be;
            server->has_bootstrap_v4 = 1;
            applied++;
        }
    }

    return applied;
}

int upstream_get_runtime_stats(upstream_client_t *client, upstream_runtime_stats_t *stats_out) {
    if (stats_out == NULL) {
        return -1;
    }

    memset(stats_out, 0, sizeof(*stats_out));
    if (client == NULL) {
        return -1;
    }

#if UPSTREAM_DOH_ENABLED
    if (client->doh_client != NULL) {
        (void)upstream_doh_client_get_pool_stats(
            client->doh_client,
            &stats_out->doh_pool_capacity,
            &stats_out->doh_pool_in_use,
            &stats_out->doh_http3_responses_total,
            &stats_out->doh_http2_responses_total,
            &stats_out->doh_http1_responses_total,
            &stats_out->doh_http_other_responses_total);
    }
#endif

#if UPSTREAM_DOT_ENABLED
    if (client->dot_client != NULL) {
        (void)upstream_dot_client_get_pool_stats(
            client->dot_client,
            &stats_out->dot_pool_capacity,
            &stats_out->dot_pool_in_use,
            &stats_out->dot_connections_alive);
    }
#endif

#if UPSTREAM_DOQ_ENABLED
    if (client->doq_client != NULL) {
        (void)upstream_doq_client_get_pool_stats(
            client->doq_client,
            &stats_out->doq_pool_capacity,
            &stats_out->doq_pool_in_use,
            &stats_out->doq_connections_alive);
    }
#endif

    return 0;
}
