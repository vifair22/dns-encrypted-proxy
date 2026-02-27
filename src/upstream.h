#ifndef UPSTREAM_H
#define UPSTREAM_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define UPSTREAM_MAX_SERVERS 8
#define UPSTREAM_MAX_URL_LEN 512

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

/*
 * Configuration for a single upstream server
 */
typedef struct {
    upstream_type_t type;
    char url[UPSTREAM_MAX_URL_LEN];  /* Full URL for DoH, or host:port for DoT */
    char host[256];                   /* Parsed hostname */
    int port;                         /* Parsed port (853 default for DoT) */
    upstream_health_t health;
} upstream_server_t;

/*
 * Upstream client configuration
 */
typedef struct {
    int timeout_ms;                  /* Per-query timeout */
    int pool_size;                   /* Connection pool size per protocol */
    int max_failures_before_unhealthy;  /* Mark unhealthy after N consecutive failures */
    int unhealthy_backoff_ms;        /* Wait time before retrying unhealthy server */
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
    
    /* Round-robin state */
    pthread_mutex_t rr_mutex;
    uint64_t next_index;
} upstream_client_t;

typedef struct {
    int doh_pool_capacity;
    int doh_pool_in_use;
    uint64_t doh_http2_responses_total;
    uint64_t doh_http1_responses_total;
    uint64_t doh_http_other_responses_total;

    int dot_pool_capacity;
    int dot_pool_in_use;
    int dot_connections_alive;

    int doq_pool_capacity;
    int doq_pool_in_use;
    int doq_connections_alive;
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

/*
 * Resolve a DNS query through upstream servers
 * 
 * Tries servers in order (round-robin start), failing over on error.
 * Respects health status and backoff policies.
 * 
 * @param client          Initialized client
 * @param query           DNS query wire format
 * @param query_len       Length of query
 * @param response_out    Output: allocated response buffer (caller frees)
 * @param response_len_out Output: length of response
 * @return 0 on success, -1 on error (all servers failed)
 */
int upstream_resolve(
    upstream_client_t *client,
    const uint8_t *query,
    size_t query_len,
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

#endif /* UPSTREAM_H */
