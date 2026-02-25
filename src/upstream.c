#define _POSIX_C_SOURCE 200809L

#include "upstream.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Forward declarations for protocol-specific functions */
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
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out);

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

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

int upstream_parse_url(const char *url, upstream_server_t *server_out) {
    if (url == NULL || server_out == NULL) {
        return -1;
    }

    memset(server_out, 0, sizeof(*server_out));
    
    /* Check for https:// (DoH) */
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
    
    /* Check for tls:// (DoT) */
    if (strncmp(url, "tls://", 6) == 0) {
        server_out->type = UPSTREAM_TYPE_DOT;
        strncpy(server_out->url, url, UPSTREAM_MAX_URL_LEN - 1);
        server_out->url[UPSTREAM_MAX_URL_LEN - 1] = '\0';
        
        /* Parse host:port */
        const char *host_start = url + 6;
        const char *colon = strchr(host_start, ':');
        const char *host_end = colon ? colon : (host_start + strlen(host_start));
        
        size_t host_len = (size_t)(host_end - host_start);
        if (host_len == 0 || host_len >= sizeof(server_out->host)) {
            return -1;
        }
        
        memcpy(server_out->host, host_start, host_len);
        server_out->host[host_len] = '\0';
        
        /* Default DoT port is 853 */
        server_out->port = 853;
        
        if (colon != NULL) {
            server_out->port = atoi(colon + 1);
            if (server_out->port <= 0 || server_out->port > 65535) {
                return -1;
            }
        }
        
        server_out->health.healthy = 1;
        return 0;
    }
    
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
    
    /* Check if backoff period has elapsed */
    uint64_t now = now_ms();
    uint64_t elapsed = now - server->health.last_failure_time;
    
    if (elapsed >= (uint64_t)config->unhealthy_backoff_ms) {
        /* Backoff elapsed, allow retry */
        return 0;
    }
    
    return 1;
}

void upstream_server_record_success(upstream_server_t *server) {
    if (server == NULL) {
        return;
    }
    
    server->health.healthy = 1;
    server->health.consecutive_failures = 0;
    server->health.last_success_time = now_ms();
    server->health.total_queries++;
}

void upstream_server_record_failure(upstream_server_t *server, const upstream_config_t *config) {
    if (server == NULL || config == NULL) {
        return;
    }
    
    server->health.consecutive_failures++;
    server->health.last_failure_time = now_ms();
    server->health.total_queries++;
    server->health.total_failures++;
    
    if (server->health.consecutive_failures >= (uint32_t)config->max_failures_before_unhealthy) {
        server->health.healthy = 0;
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
    
    /* Initialize protocol-specific clients lazily on first use */
    client->doh_client = NULL;
    client->dot_client = NULL;
    
    return 0;
}

void upstream_client_destroy(upstream_client_t *client) {
    if (client == NULL) {
        return;
    }
    
    if (client->doh_client != NULL) {
        upstream_doh_client_destroy(client->doh_client);
    }
    
    if (client->dot_client != NULL) {
        upstream_dot_client_destroy(client->dot_client);
    }
    
    pthread_mutex_destroy(&client->rr_mutex);
    memset(client, 0, sizeof(*client));
}

static int ensure_doh_client(upstream_client_t *client) {
    if (client->doh_client != NULL) {
        return 0;
    }
    return upstream_doh_client_init(&client->doh_client, &client->config);
}

static int ensure_dot_client(upstream_client_t *client) {
    if (client->dot_client != NULL) {
        return 0;
    }
    return upstream_dot_client_init(&client->dot_client, &client->config);
}

static int resolve_with_server(
    upstream_client_t *client,
    upstream_server_t *server,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    
    int result = -1;
    
    switch (server->type) {
        case UPSTREAM_TYPE_DOH:
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
            
        case UPSTREAM_TYPE_DOT:
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
    
    /* Get round-robin starting index */
    pthread_mutex_lock(&client->rr_mutex);
    uint64_t start = client->next_index;
    client->next_index++;
    pthread_mutex_unlock(&client->rr_mutex);
    
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
        
        if (resolve_with_server(client, server, query, query_len, &response, &response_len) == 0) {
            upstream_server_record_success(server);
            *response_out = response;
            *response_len_out = response_len;
            return 0;
        }
        
        upstream_server_record_failure(server, &client->config);
    }
    
    /* All servers failed - try unhealthy servers as last resort */
    for (int attempt = 0; attempt < client->server_count; attempt++) {
        int idx = (int)((start + (uint64_t)attempt) % (uint64_t)client->server_count);
        upstream_server_t *server = &client->servers[idx];
        
        if (server->health.healthy) {
            continue;  /* Already tried */
        }
        
        uint8_t *response = NULL;
        size_t response_len = 0;
        
        if (resolve_with_server(client, server, query, query_len, &response, &response_len) == 0) {
            upstream_server_record_success(server);
            *response_out = response;
            *response_len_out = response_len;
            return 0;
        }
        
        upstream_server_record_failure(server, &client->config);
    }
    
    return -1;
}

int upstream_get_runtime_stats(upstream_client_t *client, upstream_runtime_stats_t *stats_out) {
    if (stats_out == NULL) {
        return -1;
    }

    memset(stats_out, 0, sizeof(*stats_out));
    if (client == NULL) {
        return -1;
    }

    if (client->doh_client != NULL) {
        (void)upstream_doh_client_get_pool_stats(
            client->doh_client,
            &stats_out->doh_pool_capacity,
            &stats_out->doh_pool_in_use,
            &stats_out->doh_http2_responses_total,
            &stats_out->doh_http1_responses_total,
            &stats_out->doh_http_other_responses_total);
    }

    if (client->dot_client != NULL) {
        (void)upstream_dot_client_get_pool_stats(
            client->dot_client,
            &stats_out->dot_pool_capacity,
            &stats_out->dot_pool_in_use,
            &stats_out->dot_connections_alive);
    }

    return 0;
}
