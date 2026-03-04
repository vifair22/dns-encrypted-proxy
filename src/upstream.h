#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define UPSTREAM_MAX_SERVERS 8
#define UPSTREAM_MAX_URL_LEN 512
#define UPSTREAM_MAX_BOOTSTRAP_RESOLVERS 8

/*
 * Upstream server types
 */
typedef enum {
    UPSTREAM_TYPE_DOH,  /* DNS-over-HTTPS (https://) */
    UPSTREAM_TYPE_DOT,  /* DNS-over-TLS (tls://) */
    UPSTREAM_TYPE_DOQ   /* DNS-over-QUIC (quic://) */
} upstream_type_t;

/*
 * Health status for a single upstream server
 */
typedef struct {
    int healthy;                    /* 1 = healthy, 0 = unhealthy */
    uint32_t consecutive_failures;  /* Count of consecutive failures */
    uint64_t last_failure_time;     /* Unix timestamp of last failure */
    uint64_t last_success_time;     /* Unix timestamp of last success */
    uint64_t total_queries;         /* Total queries sent to this server */
    uint64_t total_failures;        /* Total failures for this server */
} upstream_health_t;

typedef enum {
    UPSTREAM_FAILURE_CLASS_UNKNOWN = 0,
    UPSTREAM_FAILURE_CLASS_DNS = 1,
    UPSTREAM_FAILURE_CLASS_NETWORK = 2,
    UPSTREAM_FAILURE_CLASS_TRANSPORT = 3,
    UPSTREAM_FAILURE_CLASS_TIMEOUT = 4,
    UPSTREAM_FAILURE_CLASS_TLS = 5,
} upstream_failure_class_t;

typedef struct {
    uint32_t bootstrap_addr_v4_be;
    uint64_t bootstrap_expires_at_ms;
    int has_bootstrap_v4;

    uint64_t stage2_next_retry_ms;

    uint32_t stage1_cached_addr_v4_be;
    uint64_t stage1_cache_expires_at_ms;
    int has_stage1_cached_v4;
    uint32_t stage1_cached_failures;

    uint64_t iterative_last_attempt_ms;

    int last_failure_class;
    uint64_t transport_retry_suppress_until_ms;

    uint8_t doh_forced_http_tier;
    uint8_t doh_upgrade_failures;
    uint64_t doh_upgrade_retry_after_ms;

    uint64_t doh_downgrade_h3_to_h2_total;
    uint64_t doh_downgrade_h3_to_h1_total;
    uint64_t doh_downgrade_h2_to_h1_total;
    uint64_t doh_upgrade_probe_attempt_total;
    uint64_t doh_upgrade_probe_success_total;
    uint64_t doh_upgrade_probe_failure_total;
} upstream_stage_state_t;

typedef struct {
    uint64_t stage1_cache_hits;
    uint64_t stage1_cache_misses;
    uint64_t stage1_cache_refreshes;
    uint64_t stage1_cache_invalidations;

    uint64_t stage2_attempts;
    uint64_t stage2_successes;
    uint64_t stage2_failures;
    uint64_t stage2_cooldowns;

    uint64_t stage3_attempts;
    uint64_t stage3_successes;
    uint64_t stage3_failures;
    uint64_t stage3_cooldowns;

    uint64_t stage2_reason_network;
    uint64_t stage2_reason_dns;
    uint64_t stage2_reason_transport;
    uint64_t stage2_reason_cooldown;
    uint64_t stage2_reason_other;

    uint64_t stage3_reason_network;
    uint64_t stage3_reason_dns;
    uint64_t stage3_reason_transport;
    uint64_t stage3_reason_cooldown;
    uint64_t stage3_reason_other;
} upstream_stage_metrics_t;

/*
 * Configuration for a single upstream server
 */
typedef struct {
    upstream_type_t type;
    char url[UPSTREAM_MAX_URL_LEN];  /* Full URL for DoH, or host:port for DoT */
    char host[256];                   /* Parsed hostname */
    int port;                         /* Parsed port (853 default for DoT) */
    upstream_stage_state_t stage;
    upstream_health_t health;
} upstream_server_t;

/*
 * Upstream client configuration
 */
typedef struct {
    int timeout_ms;                  /* Per-query timeout */
    int pool_size;                   /* Connection pool size per protocol */
    int max_inflight_doh;            /* Per-member inflight limit for DoH */
    int max_inflight_dot;            /* Per-member inflight limit for DoT */
    int max_inflight_doq;            /* Per-member inflight limit for DoQ */
    int max_failures_before_unhealthy;  /* Mark unhealthy after N consecutive failures */
    int unhealthy_backoff_ms;        /* Wait time before retrying unhealthy server */
    int iterative_bootstrap_enabled; /* Placeholder for future iterative bootstrap resolver */
} upstream_config_t;

/*
 * Forward declarations for protocol-specific clients
 */
typedef struct upstream_doh_client upstream_doh_client_t;
typedef struct upstream_dot_client upstream_dot_client_t;
typedef struct upstream_doq_client upstream_doq_client_t;

/*
 * Main upstream client - manages all upstream servers
 */
typedef struct {
    upstream_server_t servers[UPSTREAM_MAX_SERVERS];
    int server_count;
    
    upstream_config_t config;
    
    /* Protocol-specific clients (lazily initialized) */
    upstream_doh_client_t *doh_client;
    upstream_dot_client_t *dot_client;
    upstream_doq_client_t *doq_client;
    
    pthread_mutex_t stage1_cache_mutex;

    int bootstrap_resolver_count;
    char bootstrap_resolvers[UPSTREAM_MAX_BOOTSTRAP_RESOLVERS][64];

    upstream_stage_metrics_t stage_metrics;
} upstream_client_t;

typedef struct {
    int doh_pool_capacity;
    int doh_pool_in_use;
    uint64_t doh_http3_responses_total;
    uint64_t doh_http2_responses_total;
    uint64_t doh_http1_responses_total;
    uint64_t doh_http_other_responses_total;
    uint64_t doh_downgrade_h3_to_h2_total;
    uint64_t doh_downgrade_h3_to_h1_total;
    uint64_t doh_downgrade_h2_to_h1_total;
    uint64_t doh_upgrade_probe_attempt_total;
    uint64_t doh_upgrade_probe_success_total;
    uint64_t doh_upgrade_probe_failure_total;

    int dot_pool_capacity;
    int dot_pool_in_use;
    int dot_connections_alive;

    int doq_pool_capacity;
    int doq_pool_in_use;
    int doq_connections_alive;

    uint64_t stage1_cache_hits;
    uint64_t stage1_cache_misses;
    uint64_t stage1_cache_refreshes;
    uint64_t stage1_cache_invalidations;

    uint64_t stage2_attempts;
    uint64_t stage2_successes;
    uint64_t stage2_failures;
    uint64_t stage2_cooldowns;

    uint64_t stage3_attempts;
    uint64_t stage3_successes;
    uint64_t stage3_failures;
    uint64_t stage3_cooldowns;

    uint64_t stage2_reason_network;
    uint64_t stage2_reason_dns;
    uint64_t stage2_reason_transport;
    uint64_t stage2_reason_cooldown;
    uint64_t stage2_reason_other;

    uint64_t stage3_reason_network;
    uint64_t stage3_reason_dns;
    uint64_t stage3_reason_transport;
    uint64_t stage3_reason_cooldown;
    uint64_t stage3_reason_other;
} upstream_runtime_stats_t;

/*
 * Initialize upstream client with parsed server list
 * 
 * @param client      Client to initialize
 * @param urls        Array of URL strings (https://, tls://, quic://)
 * @param url_count   Number of URLs
 * @param config      Client configuration
 * @return 0 on success, -1 on error
 */
int upstream_client_init(
    upstream_client_t *client,
    const char *urls[],
    int url_count,
    const upstream_config_t *config);

/*
 * Destroy upstream client and free resources
 */
void upstream_client_destroy(upstream_client_t *client);

int upstream_resolve_on_server(
    upstream_client_t *client,
    int server_index,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out);
int upstream_resolve_on_server_with_deadline(
    upstream_client_t *client,
    int server_index,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out);

/*
 * Parse a URL string and determine the upstream type
 * 
 * Supported schemes:
 *   https://host/path  -> UPSTREAM_TYPE_DOH
 *   tls://host:port    -> UPSTREAM_TYPE_DOT (port defaults to 853)
 *   quic://host:port   -> UPSTREAM_TYPE_DOQ (port defaults to 853)
 * 
 * @param url        URL string to parse
 * @param server_out Output: parsed server configuration
 * @return 0 on success, -1 on parse error
 */
int upstream_parse_url(const char *url, upstream_server_t *server_out);

/*
 * Check if a server should be skipped due to health/backoff
 */
int upstream_server_should_skip(const upstream_server_t *server, const upstream_config_t *config);

/*
 * Record a successful query to a server
 */
void upstream_server_record_success(upstream_server_t *server);

/*
 * Record a failed query to a server
 */
void upstream_server_record_failure(upstream_server_t *server, const upstream_config_t *config);

int upstream_get_runtime_stats(upstream_client_t *client, upstream_runtime_stats_t *stats_out);
int upstream_client_set_bootstrap_ipv4(upstream_client_t *client, const char *host, uint32_t addr_v4_be);
int upstream_is_ready(const upstream_client_t *client);

#endif /* UPSTREAM_H */
