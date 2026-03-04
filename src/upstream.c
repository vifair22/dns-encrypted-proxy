#define _POSIX_C_SOURCE 200809L

#include "upstream.h"
#include "upstream_bootstrap.h"
#include "logger.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#define UPSTREAM_MAX_STAGE_ATTEMPTS_PER_QUERY 12
#define UPSTREAM_MIN_USEFUL_BUDGET_MS 25

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

static void client_counter_inc(uint64_t *counter) {
    __atomic_fetch_add(counter, 1ULL, __ATOMIC_RELAXED);
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
    server->stage.stage1_cached_failures = 0;
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

    if (server->stage.last_failure_class == UPSTREAM_FAILURE_CLASS_UNKNOWN) {
        server->health.last_failure_time = now_ms();
        server->health.total_queries++;
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
    if (client->config.max_inflight_doh <= 0) {
        client->config.max_inflight_doh = 4;
    }
    if (client->config.max_inflight_dot <= 0) {
        client->config.max_inflight_dot = 1;
    }
    if (client->config.max_inflight_doq <= 0) {
        client->config.max_inflight_doq = 1;
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
    
    if (pthread_mutex_init(&client->stage1_cache_mutex, NULL) != 0) {
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
    
    pthread_mutex_destroy(&client->stage1_cache_mutex);
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
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    
    int result = -1;
    server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_UNKNOWN;
    
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
                timeout_ms,
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
                timeout_ms,
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
                timeout_ms,
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

static int stage1_hydrate_timeout_ms(const upstream_client_t *client) {
    int hydrate_timeout_ms = client->config.timeout_ms / 4;
    if (hydrate_timeout_ms < 100) {
        hydrate_timeout_ms = 100;
    }
    if (hydrate_timeout_ms > 500) {
        hydrate_timeout_ms = 500;
    }
    return hydrate_timeout_ms;
}

static int normalize_timeout_ms(int timeout_ms) {
    if (timeout_ms <= 0) {
        return 1000;
    }
    return timeout_ms;
}

static int remaining_budget_ms(uint64_t deadline_ms, int fallback_timeout_ms) {
    if (deadline_ms == 0) {
        return normalize_timeout_ms(fallback_timeout_ms);
    }

    uint64_t now = now_ms();
    if (now >= deadline_ms) {
        return 0;
    }

    uint64_t remain = deadline_ms - now;
    if (remain > (uint64_t)INT32_MAX) {
        remain = (uint64_t)INT32_MAX;
    }
    return (int)remain;
}

static int effective_attempt_timeout_ms(uint64_t deadline_ms, int configured_timeout_ms) {
    int configured = normalize_timeout_ms(configured_timeout_ms);
    int remain = remaining_budget_ms(deadline_ms, configured);
    if (remain <= 0) {
        return 0;
    }
    if (remain < UPSTREAM_MIN_USEFUL_BUDGET_MS) {
        return 0;
    }
    return remain < configured ? remain : configured;
}

static upstream_stage1_cache_result_t prepare_stage1_cache(upstream_client_t *client, upstream_server_t *server) {
    pthread_mutex_lock(&client->stage1_cache_mutex);
    upstream_stage1_cache_result_t stage1_cache = upstream_bootstrap_stage1_prepare(server);
    pthread_mutex_unlock(&client->stage1_cache_mutex);

    if (stage1_cache == UPSTREAM_STAGE1_CACHE_HIT) {
        client_counter_inc(&client->stage_metrics.stage1_cache_hits);
    } else if (stage1_cache == UPSTREAM_STAGE1_CACHE_REFRESHED) {
        client_counter_inc(&client->stage_metrics.stage1_cache_refreshes);
    } else {
        client_counter_inc(&client->stage_metrics.stage1_cache_misses);
    }
    return stage1_cache;
}

static void maybe_hydrate_stage1_cache(
    upstream_client_t *client,
    upstream_server_t *server,
    upstream_stage1_cache_result_t stage1_cache) {
    if (stage1_cache != UPSTREAM_STAGE1_CACHE_REFRESHED) {
        return;
    }
    if (upstream_bootstrap_stage1_hydrate(client, server, stage1_hydrate_timeout_ms(client)) == 0) {
        LOGF_DEBUG("Stage1 cache hydrated with DNS TTL: host=%s", server->host);
    }
}

static void note_stage1_failure(upstream_client_t *client, upstream_server_t *server) {
    pthread_mutex_lock(&client->stage1_cache_mutex);
    if (server->stage.has_stage1_cached_v4) {
        server->stage.stage1_cached_failures++;
        if (server->stage.stage1_cached_failures >= 2) {
            upstream_bootstrap_stage1_invalidate(server);
            client_counter_inc(&client->stage_metrics.stage1_cache_invalidations);
        }
    }
    pthread_mutex_unlock(&client->stage1_cache_mutex);
}

typedef enum {
    UPSTREAM_REASON_CLASS_NETWORK = 0,
    UPSTREAM_REASON_CLASS_DNS = 1,
    UPSTREAM_REASON_CLASS_TRANSPORT = 2,
    UPSTREAM_REASON_CLASS_COOLDOWN = 3,
    UPSTREAM_REASON_CLASS_OTHER = 4,
} upstream_reason_class_t;

static int reason_in_list(const char *reason, const char *const *list, size_t list_len) {
    if (reason == NULL || list == NULL) {
        return 0;
    }
    for (size_t i = 0; i < list_len; i++) {
        if (strcmp(reason, list[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static upstream_reason_class_t classify_stage_reason(const char *reason) {
    static const char *const dns_reasons[] = {
        "dns_resolve_failed",
        "dns_rcode_nonzero",
        "invalid_dns_response",
        "invalid_question_section",
        "invalid_answer_section",
        "invalid_rdata_length",
        "no_a_answer",
        "txid_mismatch",
        "invalid_hostname",
    };
    static const char *const network_reasons[] = {
        "invalid_resolver_ip",
        "socket_create_failed",
        "sendto_failed",
        "poll_timeout",
        "poll_failed",
        "poll_revents_error",
        "recv_short_or_failed",
        "iterative_resolve_failed",
        "timeout",
    };
    static const char *const transport_reasons[] = {
        "transport_connect_failed",
        "transport_io_failed",
        "transport_failed",
        "transport_retry_failed",
        "tls_handshake_failed",
        "protocol_exchange_failed",
        "upstream_http_status",
    };

    if (reason == NULL) {
        return UPSTREAM_REASON_CLASS_OTHER;
    }
    if (strcmp(reason, "cooldown") == 0) {
        return UPSTREAM_REASON_CLASS_COOLDOWN;
    }
    if (reason_in_list(reason, dns_reasons, sizeof(dns_reasons) / sizeof(dns_reasons[0]))) {
        return UPSTREAM_REASON_CLASS_DNS;
    }
    if (reason_in_list(reason, network_reasons, sizeof(network_reasons) / sizeof(network_reasons[0]))) {
        return UPSTREAM_REASON_CLASS_NETWORK;
    }
    if (reason_in_list(reason, transport_reasons, sizeof(transport_reasons) / sizeof(transport_reasons[0]))) {
        return UPSTREAM_REASON_CLASS_TRANSPORT;
    }
    return UPSTREAM_REASON_CLASS_OTHER;
}

static void note_stage_reason(upstream_client_t *client, int stage, const char *reason) {
    if (client == NULL || reason == NULL) {
        return;
    }

    upstream_reason_class_t reason_class = classify_stage_reason(reason);
    if (stage == 2) {
        switch (reason_class) {
            case UPSTREAM_REASON_CLASS_NETWORK:
                client_counter_inc(&client->stage_metrics.stage2_reason_network);
                break;
            case UPSTREAM_REASON_CLASS_DNS:
                client_counter_inc(&client->stage_metrics.stage2_reason_dns);
                break;
            case UPSTREAM_REASON_CLASS_TRANSPORT:
                client_counter_inc(&client->stage_metrics.stage2_reason_transport);
                break;
            case UPSTREAM_REASON_CLASS_COOLDOWN:
                client_counter_inc(&client->stage_metrics.stage2_reason_cooldown);
                break;
            case UPSTREAM_REASON_CLASS_OTHER:
            default:
                client_counter_inc(&client->stage_metrics.stage2_reason_other);
                break;
        }
    } else {
        switch (reason_class) {
            case UPSTREAM_REASON_CLASS_NETWORK:
                client_counter_inc(&client->stage_metrics.stage3_reason_network);
                break;
            case UPSTREAM_REASON_CLASS_DNS:
                client_counter_inc(&client->stage_metrics.stage3_reason_dns);
                break;
            case UPSTREAM_REASON_CLASS_TRANSPORT:
                client_counter_inc(&client->stage_metrics.stage3_reason_transport);
                break;
            case UPSTREAM_REASON_CLASS_COOLDOWN:
                client_counter_inc(&client->stage_metrics.stage3_reason_cooldown);
                break;
            case UPSTREAM_REASON_CLASS_OTHER:
            default:
                client_counter_inc(&client->stage_metrics.stage3_reason_other);
                break;
        }
    }
}

static void format_ipv4(uint32_t addr_v4_be, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    struct in_addr addr;
    addr.s_addr = addr_v4_be;
    if (inet_ntop(AF_INET, &addr, out, out_len) == NULL) {
        out[0] = '\0';
    }
}

static uint64_t stage_cooldown_remaining_ms(const upstream_server_t *server, int stage_id) {
    if (server == NULL) {
        return 0;
    }
    uint64_t now = now_ms();
    if (stage_id == 2) {
        if (server->stage.stage2_next_retry_ms > now) {
            return server->stage.stage2_next_retry_ms - now;
        }
        return 0;
    }
    if (stage_id == 3) {
        if (server->stage.iterative_last_attempt_ms == 0 || now <= server->stage.iterative_last_attempt_ms) {
            return 0;
        }
        uint64_t elapsed = now - server->stage.iterative_last_attempt_ms;
        if (elapsed >= UPSTREAM_STAGE3_RETRY_COOLDOWN_MS) {
            return 0;
        }
        return UPSTREAM_STAGE3_RETRY_COOLDOWN_MS - elapsed;
    }
    return 0;
}

static void log_stage_event_impl(
    const char *caller_func,
    const upstream_server_t *server,
    int stage_id,
    const char *stage,
    const char *action,
    const char *reason,
    const char *detail,
    int timeout_ms) {
    uint64_t cooldown_ms = stage_cooldown_remaining_ms(server, stage_id);
    char ip_text[INET_ADDRSTRLEN];
    ip_text[0] = '\0';
    if (server->stage.has_bootstrap_v4) {
        format_ipv4(server->stage.bootstrap_addr_v4_be, ip_text, sizeof(ip_text));
    }

    logger_logf(
        caller_func,
        "WARN",
        "Upstream stage event: host=%s type=%s stage=%s action=%s reason=%s detail=%s timeout_ms=%d cooldown_ms=%llu override_ip=%s",
        server->host,
        upstream_type_name(server->type),
        stage,
        action,
        reason != NULL ? reason : "none",
        detail != NULL ? detail : "none",
        timeout_ms,
        (unsigned long long)cooldown_ms,
        ip_text[0] != '\0' ? ip_text : "none");
}

#define LOG_STAGE_EVENT(server, stage_id, stage, action, reason, detail, timeout_ms) \
    log_stage_event_impl(__func__, server, stage_id, stage, action, reason, detail, timeout_ms)

static int consume_retry_budget(int *budget, const upstream_server_t *server, const char *phase) {
    if (budget == NULL || server == NULL || phase == NULL) {
        return -1;
    }
    if (*budget <= 0) {
        LOGF_WARN("Upstream retry budget exhausted: host=%s phase=%s", server->host, phase);
        return -1;
    }
    (*budget)--;
    return 0;
}

static int should_try_stage3_after_stage2_failure(const char *stage2_reason) {
    upstream_reason_class_t reason_class = classify_stage_reason(stage2_reason);
    return reason_class == UPSTREAM_REASON_CLASS_DNS || reason_class == UPSTREAM_REASON_CLASS_NETWORK;
}

static int resolve_server_with_fallback(
    upstream_client_t *client,
    upstream_server_t *server,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out,
    int *retry_budget,
    int unhealthy_probe,
    uint64_t deadline_ms) {
    uint8_t *response = NULL;
    size_t response_len = 0;
    int timeout_ms = effective_attempt_timeout_ms(deadline_ms, client->config.timeout_ms);

    if (timeout_ms <= 0) {
        LOG_STAGE_EVENT(server, 1, "stage1", "skipped", "budget_exhausted", "insufficient_remaining_budget", 0);
        server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_TIMEOUT;
        return -1;
    }

    upstream_stage1_cache_result_t stage1_cache = prepare_stage1_cache(client, server);

    if (unhealthy_probe) {
        LOGF_DEBUG("Upstream connect retry unhealthy: host=%s type=%s", server->host, upstream_type_name(server->type));
    } else {
        LOGF_DEBUG("Upstream connect stage1 local resolver: host=%s type=%s", server->host, upstream_type_name(server->type));
    }

    if (consume_retry_budget(retry_budget, server, "stage1") == 0 &&
        resolve_with_server(client, server, timeout_ms, query, query_len, &response, &response_len) == 0) {
        maybe_hydrate_stage1_cache(client, server, stage1_cache);
        upstream_server_record_success(server);
        *response_out = response;
        *response_len_out = response_len;
        return 0;
    }

    if (unhealthy_probe) {
        LOGF_WARN("Upstream unhealthy retry failed: host=%s type=%s", server->host, upstream_type_name(server->type));
    } else {
        LOGF_WARN("Upstream failed: host=%s type=%s", server->host, upstream_type_name(server->type));
    }

    note_stage1_failure(client, server);

    timeout_ms = effective_attempt_timeout_ms(deadline_ms, client->config.timeout_ms);
    if (timeout_ms <= 0) {
        LOG_STAGE_EVENT(server, 2, "stage2", "skipped", "budget_exhausted", "insufficient_remaining_budget", 0);
        server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_TIMEOUT;
        upstream_server_record_failure(server, &client->config);
        return -1;
    }

    LOG_STAGE_EVENT(server, 2, "stage2", "enter", "stage1_failed", NULL, timeout_ms);
    client_counter_inc(&client->stage_metrics.stage2_attempts);
    const char *stage2_reason = NULL;
    if (upstream_bootstrap_try_stage2(client, server, timeout_ms, &stage2_reason) == 0) {
        client_counter_inc(&client->stage_metrics.stage2_successes);
        timeout_ms = effective_attempt_timeout_ms(deadline_ms, client->config.timeout_ms);
        if (consume_retry_budget(retry_budget, server, "stage2") == 0 &&
            timeout_ms > 0 &&
            resolve_with_server(client, server, timeout_ms, query, query_len, &response, &response_len) == 0) {
            upstream_server_record_success(server);
            *response_out = response;
            *response_len_out = response_len;
            return 0;
        }
        client_counter_inc(&client->stage_metrics.stage2_failures);
        note_stage_reason(client, 2, "transport_retry_failed");
        LOG_STAGE_EVENT(
            server,
            2,
            "stage2",
            "retry_failed",
            "transport_retry_failed",
            stage2_reason,
            timeout_ms);
        LOG_STAGE_EVENT(
            server,
            3,
            "stage3",
            "skipped",
            "stage2_resolved_transport_failed",
            stage2_reason,
            timeout_ms);
        upstream_server_record_failure(server, &client->config);
        return -1;
    } else {
        client_counter_inc(&client->stage_metrics.stage2_failures);
        if (stage2_reason != NULL && strcmp(stage2_reason, "cooldown") == 0) {
            client_counter_inc(&client->stage_metrics.stage2_cooldowns);
        }
        note_stage_reason(client, 2, stage2_reason);
        LOG_STAGE_EVENT(server, 2, "stage2", "failed", stage2_reason, NULL, timeout_ms);
    }

    if (client->config.iterative_bootstrap_enabled && should_try_stage3_after_stage2_failure(stage2_reason)) {
        timeout_ms = effective_attempt_timeout_ms(deadline_ms, client->config.timeout_ms);
        if (timeout_ms <= 0) {
            LOG_STAGE_EVENT(server, 3, "stage3", "skipped", "budget_exhausted", "insufficient_remaining_budget", 0);
            server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_TIMEOUT;
            upstream_server_record_failure(server, &client->config);
            return -1;
        }

        LOG_STAGE_EVENT(server, 3, "stage3", "enter", "stage2_failed", stage2_reason, timeout_ms);
        client_counter_inc(&client->stage_metrics.stage3_attempts);

        const char *stage3_reason = NULL;
        if (upstream_bootstrap_try_stage3(server, timeout_ms, &stage3_reason) == 0) {
            client_counter_inc(&client->stage_metrics.stage3_successes);
            LOGF_INFO("Upstream stage3 iterative bootstrap resolved host=%s", server->host);
            timeout_ms = effective_attempt_timeout_ms(deadline_ms, client->config.timeout_ms);
            if (consume_retry_budget(retry_budget, server, "stage3") == 0 &&
                timeout_ms > 0 &&
                resolve_with_server(client, server, timeout_ms, query, query_len, &response, &response_len) == 0) {
                upstream_server_record_success(server);
                *response_out = response;
                *response_len_out = response_len;
                return 0;
            }
            client_counter_inc(&client->stage_metrics.stage3_failures);
            note_stage_reason(client, 3, "transport_retry_failed");
            LOG_STAGE_EVENT(
                server,
                3,
                "stage3",
                "retry_failed",
                "transport_retry_failed",
                stage3_reason,
                timeout_ms);
        } else {
            client_counter_inc(&client->stage_metrics.stage3_failures);
            if (stage3_reason != NULL && strcmp(stage3_reason, "cooldown") == 0) {
                client_counter_inc(&client->stage_metrics.stage3_cooldowns);
            }
            note_stage_reason(client, 3, stage3_reason);
            LOG_STAGE_EVENT(server, 3, "stage3", "failed", stage3_reason, NULL, timeout_ms);
        }
    } else if (client->config.iterative_bootstrap_enabled) {
        timeout_ms = effective_attempt_timeout_ms(deadline_ms, client->config.timeout_ms);
        LOG_STAGE_EVENT(
            server,
            3,
            "stage3",
            "skipped",
            "non_lookup_stage2_failure",
            stage2_reason,
            timeout_ms);
    }

    upstream_server_record_failure(server, &client->config);
    return -1;
}

int upstream_resolve_on_server(
    upstream_client_t *client,
    int server_index,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    int timeout_ms = normalize_timeout_ms(client != NULL ? client->config.timeout_ms : 0);
    uint64_t deadline_ms = now_ms() + (uint64_t)timeout_ms;
    return upstream_resolve_on_server_with_deadline(
        client,
        server_index,
        query,
        query_len,
        deadline_ms,
        response_out,
        response_len_out);
}

int upstream_resolve_on_server_with_deadline(
    upstream_client_t *client,
    int server_index,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (client == NULL || query == NULL || query_len == 0 ||
        response_out == NULL || response_len_out == NULL ||
        server_index < 0 || server_index >= client->server_count) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    upstream_server_t *server = &client->servers[server_index];
    int retry_budget = UPSTREAM_MAX_STAGE_ATTEMPTS_PER_QUERY;

    if (!upstream_server_should_skip(server, &client->config)) {
        if (resolve_server_with_fallback(
                client,
                server,
                query,
                query_len,
                response_out,
                response_len_out,
                &retry_budget,
                0,
                deadline_ms)
            == 0) {
            return 0;
        }
    }

    if (!server->health.healthy) {
        if (resolve_server_with_fallback(
                client,
                server,
                query,
                query_len,
                response_out,
                response_len_out,
                &retry_budget,
                1,
                deadline_ms)
            == 0) {
            return 0;
        }
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
            server->stage.bootstrap_addr_v4_be = addr_v4_be;
            server->stage.has_bootstrap_v4 = 1;
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

    stats_out->stage1_cache_hits = __atomic_load_n(&client->stage_metrics.stage1_cache_hits, __ATOMIC_RELAXED);
    stats_out->stage1_cache_misses = __atomic_load_n(&client->stage_metrics.stage1_cache_misses, __ATOMIC_RELAXED);
    stats_out->stage1_cache_refreshes = __atomic_load_n(&client->stage_metrics.stage1_cache_refreshes, __ATOMIC_RELAXED);
    stats_out->stage1_cache_invalidations = __atomic_load_n(&client->stage_metrics.stage1_cache_invalidations, __ATOMIC_RELAXED);
    stats_out->stage2_attempts = __atomic_load_n(&client->stage_metrics.stage2_attempts, __ATOMIC_RELAXED);
    stats_out->stage2_successes = __atomic_load_n(&client->stage_metrics.stage2_successes, __ATOMIC_RELAXED);
    stats_out->stage2_failures = __atomic_load_n(&client->stage_metrics.stage2_failures, __ATOMIC_RELAXED);
    stats_out->stage2_cooldowns = __atomic_load_n(&client->stage_metrics.stage2_cooldowns, __ATOMIC_RELAXED);
    stats_out->stage3_attempts = __atomic_load_n(&client->stage_metrics.stage3_attempts, __ATOMIC_RELAXED);
    stats_out->stage3_successes = __atomic_load_n(&client->stage_metrics.stage3_successes, __ATOMIC_RELAXED);
    stats_out->stage3_failures = __atomic_load_n(&client->stage_metrics.stage3_failures, __ATOMIC_RELAXED);
    stats_out->stage3_cooldowns = __atomic_load_n(&client->stage_metrics.stage3_cooldowns, __ATOMIC_RELAXED);
    stats_out->stage2_reason_network = __atomic_load_n(&client->stage_metrics.stage2_reason_network, __ATOMIC_RELAXED);
    stats_out->stage2_reason_dns = __atomic_load_n(&client->stage_metrics.stage2_reason_dns, __ATOMIC_RELAXED);
    stats_out->stage2_reason_transport = __atomic_load_n(&client->stage_metrics.stage2_reason_transport, __ATOMIC_RELAXED);
    stats_out->stage2_reason_cooldown = __atomic_load_n(&client->stage_metrics.stage2_reason_cooldown, __ATOMIC_RELAXED);
    stats_out->stage2_reason_other = __atomic_load_n(&client->stage_metrics.stage2_reason_other, __ATOMIC_RELAXED);
    stats_out->stage3_reason_network = __atomic_load_n(&client->stage_metrics.stage3_reason_network, __ATOMIC_RELAXED);
    stats_out->stage3_reason_dns = __atomic_load_n(&client->stage_metrics.stage3_reason_dns, __ATOMIC_RELAXED);
    stats_out->stage3_reason_transport = __atomic_load_n(&client->stage_metrics.stage3_reason_transport, __ATOMIC_RELAXED);
    stats_out->stage3_reason_cooldown = __atomic_load_n(&client->stage_metrics.stage3_reason_cooldown, __ATOMIC_RELAXED);
    stats_out->stage3_reason_other = __atomic_load_n(&client->stage_metrics.stage3_reason_other, __ATOMIC_RELAXED);

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

    for (int i = 0; i < client->server_count; i++) {
        const upstream_server_t *server = &client->servers[i];
        if (server->type != UPSTREAM_TYPE_DOH) {
            continue;
        }
        stats_out->doh_downgrade_h3_to_h2_total +=
            __atomic_load_n(&server->stage.doh_downgrade_h3_to_h2_total, __ATOMIC_RELAXED);
        stats_out->doh_downgrade_h3_to_h1_total +=
            __atomic_load_n(&server->stage.doh_downgrade_h3_to_h1_total, __ATOMIC_RELAXED);
        stats_out->doh_downgrade_h2_to_h1_total +=
            __atomic_load_n(&server->stage.doh_downgrade_h2_to_h1_total, __ATOMIC_RELAXED);
        stats_out->doh_upgrade_probe_attempt_total +=
            __atomic_load_n(&server->stage.doh_upgrade_probe_attempt_total, __ATOMIC_RELAXED);
        stats_out->doh_upgrade_probe_success_total +=
            __atomic_load_n(&server->stage.doh_upgrade_probe_success_total, __ATOMIC_RELAXED);
        stats_out->doh_upgrade_probe_failure_total +=
            __atomic_load_n(&server->stage.doh_upgrade_probe_failure_total, __ATOMIC_RELAXED);
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

int upstream_is_ready(const upstream_client_t *client) {
    if (client == NULL || client->server_count <= 0) {
        return 0;
    }

    for (int i = 0; i < client->server_count; i++) {
        const upstream_server_t *server = &client->servers[i];
        if (server->health.last_success_time != 0) {
            return 1;
        }
        if (server->stage.has_stage1_cached_v4 || server->stage.has_bootstrap_v4) {
            return 1;
        }
    }

    return 0;
}
