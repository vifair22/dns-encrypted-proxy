#define _POSIX_C_SOURCE 200809L

#include "upstream.h"
#include "upstream_doh.h"
#include "dns_message.h"
#include "logger.h"

#include <curl/curl.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define DOH_MIN_ATTEMPT_TIMEOUT_MS 200
#define DOH_TRANSPORT_SUPPRESS_MS 5000ULL
#define DOH_UPGRADE_BACKOFF_BASE_MS (10ULL * 60ULL * 1000ULL)
#define DOH_UPGRADE_BACKOFF_MAX_MS (6ULL * 60ULL * 60ULL * 1000ULL)
/* Number of consecutive h3 attempt failures required before pinning to h2.
 * Until the threshold is met, h3 is retried first on every call and h2 is
 * used only as the in-call fallback. Prevents a single transient h3 blip
 * (UDP packet drop, brief firewall flap) from costing the long backoff. */
#define DOH_DOWNGRADE_H3_CONSECUTIVE_THRESHOLD 3

typedef enum {
    DOH_HTTP_TIER_H3 = 0,
    DOH_HTTP_TIER_H2 = 1,
    DOH_HTTP_TIER_H1 = 2,
} doh_http_tier_t;

static const char *doh_tier_name(doh_http_tier_t tier);

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/*
 * DoH client implementation
 * 
 * Uses libcurl with HTTP/2 for DNS-over-HTTPS queries.
 * Maintains a connection pool for reuse.
 */

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buffer_t;

typedef struct {
    CURLcode curl_rc;
    long http_status;
    size_t response_len;
    int timeout_ms;
    int attempt_tier;
    int used_override_v4;
    uint32_t override_addr_v4_be;
} doh_attempt_error_t;

static void format_ipv4(uint32_t addr_v4_be, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    struct in_addr addr;
    addr.s_addr = addr_v4_be;
    if (inet_ntop(AF_INET, &addr, out, (socklen_t)out_len) == NULL) {
        out[0] = '\0';
    }
}

static const char *doh_curl_code_string(CURLcode rc) {
    switch (rc) {
        case CURLE_OK:
            return "ok";
        case CURLE_COULDNT_RESOLVE_HOST:
            return "couldnt_resolve_host";
        case CURLE_COULDNT_CONNECT:
            return "couldnt_connect";
        case CURLE_OPERATION_TIMEDOUT:
            return "operation_timedout";
        case CURLE_SSL_CONNECT_ERROR:
            return "ssl_connect_error";
        case CURLE_PEER_FAILED_VERIFICATION:
            return "peer_failed_verification";
        case CURLE_RECV_ERROR:
            return "recv_error";
        case CURLE_SEND_ERROR:
            return "send_error";
        default:
            return "other";
    }
}

static const char *doh_failure_reason(CURLcode rc, long http_status, size_t response_len) {
    if (rc == CURLE_OPERATION_TIMEDOUT) {
        return "timeout";
    }
    if (rc == CURLE_COULDNT_RESOLVE_HOST) {
        return "dns_resolve_failed";
    }
    if (rc == CURLE_COULDNT_CONNECT) {
        return "transport_connect_failed";
    }
    if (rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_PEER_FAILED_VERIFICATION) {
        return "tls_handshake_failed";
    }
    if (rc == CURLE_SEND_ERROR || rc == CURLE_RECV_ERROR) {
        return "transport_io_failed";
    }
    if (rc != CURLE_OK) {
        return "transport_failed";
    }
    if (http_status != 200) {
        return "upstream_http_status";
    }
    if (response_len == 0) {
        return "empty_response";
    }
    return "unknown";
}

static upstream_failure_class_t doh_failure_class(CURLcode rc, long http_status, size_t response_len) {
    const char *reason = doh_failure_reason(rc, http_status, response_len);
    if (strcmp(reason, "timeout") == 0) {
        return UPSTREAM_FAILURE_CLASS_TIMEOUT;
    }
    if (strcmp(reason, "dns_resolve_failed") == 0) {
        return UPSTREAM_FAILURE_CLASS_DNS;
    }
    if (strcmp(reason, "tls_handshake_failed") == 0) {
        return UPSTREAM_FAILURE_CLASS_TLS;
    }
    if (strcmp(reason, "transport_connect_failed") == 0 ||
        strcmp(reason, "transport_io_failed") == 0 ||
        strcmp(reason, "transport_failed") == 0 ||
        strcmp(reason, "empty_response") == 0) {
        return UPSTREAM_FAILURE_CLASS_TRANSPORT;
    }
    if (strcmp(reason, "upstream_http_status") == 0) {
        return UPSTREAM_FAILURE_CLASS_UNKNOWN;
    }
    return UPSTREAM_FAILURE_CLASS_UNKNOWN;
}

static int failure_class_is_transport_like(upstream_failure_class_t cls) {
    return cls == UPSTREAM_FAILURE_CLASS_TRANSPORT ||
           cls == UPSTREAM_FAILURE_CLASS_TIMEOUT ||
           cls == UPSTREAM_FAILURE_CLASS_TLS;
}

static int next_attempt_timeout_ms(uint64_t deadline_ms, int attempts_left) {
    if (attempts_left <= 0) {
        return -1;
    }
    uint64_t now = now_ms();
    if (now >= deadline_ms) {
        return -1;
    }
    uint64_t remaining = deadline_ms - now;
    int t = (int)(remaining / (uint64_t)attempts_left);
    if (t < DOH_MIN_ATTEMPT_TIMEOUT_MS && remaining >= DOH_MIN_ATTEMPT_TIMEOUT_MS) {
        t = DOH_MIN_ATTEMPT_TIMEOUT_MS;
    }
    if ((uint64_t)t > remaining) {
        t = (int)remaining;
    }
    if (t <= 0) {
        t = 1;
    }
    return t;
}

static void log_doh_attempt_failure_impl(
    const char *caller_func,
    const char *phase,
    const upstream_server_t *server,
    const doh_attempt_error_t *err) {
    if (phase == NULL || server == NULL || err == NULL) {
        return;
    }

    char ip_text[INET_ADDRSTRLEN];
    ip_text[0] = '\0';
    if (err->used_override_v4) {
        format_ipv4(err->override_addr_v4_be, ip_text, sizeof(ip_text));
    }

    const char *reason = doh_failure_reason(err->curl_rc, err->http_status, err->response_len);
    logger_logf(
        caller_func,
        "WARN",
        "DoH %s failed: host=%s reason=%s timeout_ms=%d override_ip=%s detail=curl=%d(%s),http=%ld,body_len=%zu",
        phase,
        server->host,
        reason,
        err->timeout_ms,
        err->used_override_v4 ? ip_text : "none",
        (int)err->curl_rc,
        doh_curl_code_string(err->curl_rc),
        err->http_status,
        err->response_len);

    if (err->attempt_tier >= 0) {
        logger_logf(
            caller_func,
            "DEBUG",
            "DoH %s protocol_tier=%s",
            phase,
            doh_tier_name((doh_http_tier_t)err->attempt_tier));
    }
}

#define LOG_DOH_ATTEMPT_FAILURE(phase, server, err) \
    log_doh_attempt_failure_impl(__func__, phase, server, err)

struct upstream_doh_client {
    CURL **pool_handles;
    int *pool_in_use;
    int pool_size;
    pthread_mutex_t pool_mutex;
    pthread_cond_t pool_cond;
    int initialized;
    atomic_uint_fast64_t http3_responses_total;
    atomic_uint_fast64_t http2_responses_total;
    atomic_uint_fast64_t http1_responses_total;
    atomic_uint_fast64_t http_other_responses_total;
};

static int curl_http_version_is_h3(long http_version) {
#if !defined(CURL_HTTP_VERSION_3) && !defined(CURL_HTTP_VERSION_3ONLY)
    (void)http_version;
#endif
#ifdef CURL_HTTP_VERSION_3
    if (http_version == CURL_HTTP_VERSION_3) {
        return 1;
    }
#endif
#ifdef CURL_HTTP_VERSION_3ONLY
    if (http_version == CURL_HTTP_VERSION_3ONLY) {
        return 1;
    }
#endif
    return 0;
}

static int curl_http_version_is_h2(long http_version) {
#if !defined(CURL_HTTP_VERSION_2_0) && !defined(CURL_HTTP_VERSION_2) && !defined(CURL_HTTP_VERSION_2TLS) && !defined(CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE)
    (void)http_version;
#endif
#ifdef CURL_HTTP_VERSION_2_0
    if (http_version == CURL_HTTP_VERSION_2_0) {
        return 1;
    }
#endif
#ifdef CURL_HTTP_VERSION_2
    if (http_version == CURL_HTTP_VERSION_2) {
        return 1;
    }
#endif
#ifdef CURL_HTTP_VERSION_2TLS
    if (http_version == CURL_HTTP_VERSION_2TLS) {
        return 1;
    }
#endif
#ifdef CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
    if (http_version == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE) {
        return 1;
    }
#endif
    return 0;
}

static int curl_http_version_is_h1(long http_version) {
#if !defined(CURL_HTTP_VERSION_1_0) && !defined(CURL_HTTP_VERSION_1_1)
    (void)http_version;
#endif
#ifdef CURL_HTTP_VERSION_1_0
    if (http_version == CURL_HTTP_VERSION_1_0) {
        return 1;
    }
#endif
#ifdef CURL_HTTP_VERSION_1_1
    if (http_version == CURL_HTTP_VERSION_1_1) {
        return 1;
    }
#endif
    return 0;
}

static long doh_preferred_http_version(void) {
#ifdef CURL_HTTP_VERSION_3
    return CURL_HTTP_VERSION_3;
#elif defined(CURL_HTTP_VERSION_3ONLY)
    return CURL_HTTP_VERSION_3ONLY;
#elif defined(CURL_HTTP_VERSION_2TLS)
    return CURL_HTTP_VERSION_2TLS;
#elif defined(CURL_HTTP_VERSION_2)
    return CURL_HTTP_VERSION_2;
#else
    return CURL_HTTP_VERSION_NONE;
#endif
}

static long doh_http_version_for_tier(doh_http_tier_t tier) {
    switch (tier) {
        case DOH_HTTP_TIER_H3:
#ifdef CURL_HTTP_VERSION_3
            return CURL_HTTP_VERSION_3;
#elif defined(CURL_HTTP_VERSION_3ONLY)
            return CURL_HTTP_VERSION_3ONLY;
#elif defined(CURL_HTTP_VERSION_2TLS)
            return CURL_HTTP_VERSION_2TLS;
#elif defined(CURL_HTTP_VERSION_2)
            return CURL_HTTP_VERSION_2;
#elif defined(CURL_HTTP_VERSION_1_1)
            return CURL_HTTP_VERSION_1_1;
#else
            return CURL_HTTP_VERSION_NONE;
#endif
        case DOH_HTTP_TIER_H2:
#ifdef CURL_HTTP_VERSION_2TLS
            return CURL_HTTP_VERSION_2TLS;
#elif defined(CURL_HTTP_VERSION_2)
            return CURL_HTTP_VERSION_2;
#elif defined(CURL_HTTP_VERSION_2_0)
            return CURL_HTTP_VERSION_2_0;
#elif defined(CURL_HTTP_VERSION_1_1)
            return CURL_HTTP_VERSION_1_1;
#else
            return CURL_HTTP_VERSION_NONE;
#endif
        case DOH_HTTP_TIER_H1:
#ifdef CURL_HTTP_VERSION_1_1
            return CURL_HTTP_VERSION_1_1;
#elif defined(CURL_HTTP_VERSION_1_0)
            return CURL_HTTP_VERSION_1_0;
#else
            return CURL_HTTP_VERSION_NONE;
#endif
        default:
            return doh_preferred_http_version();
    }
}

static const char *doh_tier_name(doh_http_tier_t tier) {
    switch (tier) {
        case DOH_HTTP_TIER_H3:
            return "h3";
        case DOH_HTTP_TIER_H2:
            return "h2";
        case DOH_HTTP_TIER_H1:
            return "h1";
        default:
            return "unknown";
    }
}

static uint64_t doh_upgrade_backoff_ms(uint8_t failures) {
    uint8_t shift = failures > 10 ? 10 : failures;
    uint64_t backoff = DOH_UPGRADE_BACKOFF_BASE_MS << shift;
    if (backoff > DOH_UPGRADE_BACKOFF_MAX_MS) {
        backoff = DOH_UPGRADE_BACKOFF_MAX_MS;
    }
    return backoff;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    buffer_t *buffer = (buffer_t *)userdata;
    size_t chunk = size * nmemb;

    /*
     * Geometric growth keeps amortized append cost low and reduces realloc
     * churn under variable upstream response sizes.
     */
    if (buffer->len + chunk > buffer->cap) {
        size_t new_cap = buffer->cap == 0 ? 2048 : buffer->cap;
        while (new_cap < buffer->len + chunk) {
            new_cap *= 2;
        }

        uint8_t *new_data = realloc(buffer->data, new_cap);
        if (new_data == NULL) {
            return 0;
        }

        buffer->data = new_data;
        buffer->cap = new_cap;
    }

    if (chunk > 0) {
        memcpy(buffer->data + buffer->len, ptr, chunk);
        buffer->len += chunk;
    }

    return chunk;
}

static int pool_acquire(upstream_doh_client_t *client, CURL **handle_out, int *slot_out) {
    /*
     * Blocking acquire gives simple backpressure: callers wait instead of
     * creating unbounded transient handles, preserving connection reuse and
     * predictable memory/socket usage under load.
     */
    pthread_mutex_lock(&client->pool_mutex);

    for (;;) {
        for (int i = 0; i < client->pool_size; i++) {
            if (!client->pool_in_use[i]) {
                client->pool_in_use[i] = 1;
                *handle_out = client->pool_handles[i];
                *slot_out = i;
                pthread_mutex_unlock(&client->pool_mutex);
                return 0;
            }
        }

        pthread_cond_wait(&client->pool_cond, &client->pool_mutex);
    }
}

static void pool_release(upstream_doh_client_t *client, int slot) {
    pthread_mutex_lock(&client->pool_mutex);
    client->pool_in_use[slot] = 0;
    pthread_cond_signal(&client->pool_cond);
    pthread_mutex_unlock(&client->pool_mutex);
}

static int doh_post_with_handle(
    upstream_doh_client_t *client,
    CURL *curl,
    const upstream_server_t *server,
    doh_http_tier_t http_tier,
    int use_override_v4,
    uint32_t override_addr_v4_be,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out,
    doh_attempt_error_t *err_out) {

    if (err_out != NULL) {
        memset(err_out, 0, sizeof(*err_out));
        err_out->curl_rc = CURLE_OK;
        err_out->timeout_ms = timeout_ms;
        err_out->attempt_tier = (int)http_tier;
        err_out->used_override_v4 = use_override_v4;
        err_out->override_addr_v4_be = override_addr_v4_be;
    }
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/dns-message");
    if (headers == NULL) {
        return -1;
    }
    struct curl_slist *temp = curl_slist_append(headers, "Accept: application/dns-message");
    if (temp == NULL) {
        curl_slist_free_all(headers);
        return -1;
    }
    headers = temp;

    buffer_t response = {0};

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    /* Test hooks are opt-in and only alter transport selection/verification. */
    const char *force_http1 = getenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1");
    if (force_http1 != NULL && *force_http1 != '\0') {
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    } else {
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, doh_http_version_for_tier(http_tier));
    }

    const char *insecure_tls = getenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS");
    if (insecure_tls != NULL && *insecure_tls != '\0') {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    curl_easy_setopt(curl, CURLOPT_URL, server->url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)query_len);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dns-encrypted-proxy/0.2");

    struct curl_slist *resolve = NULL;
    if (use_override_v4) {
        struct in_addr addr;
        addr.s_addr = override_addr_v4_be;
        char ip_text[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr, ip_text, sizeof(ip_text)) != NULL) {
            char resolve_entry[320];
            if (snprintf(resolve_entry, sizeof(resolve_entry), "%s:%d:%s", server->host, server->port, ip_text) > 0) {
                resolve = curl_slist_append(NULL, resolve_entry);
                if (resolve != NULL) {
                    curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
                }
            }
        }
    }

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    long http_version = 0;
    (void)curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &http_version);

    curl_slist_free_all(headers);
    if (resolve != NULL) {
        curl_slist_free_all(resolve);
    }

    if (err_out != NULL) {
        err_out->curl_rc = rc;
        err_out->http_status = status;
        err_out->response_len = response.len;
    }

    /* Empty body is treated as transport failure for resolver semantics. */
    if (rc != CURLE_OK || status != 200 || response.len == 0) {
        free(response.data);
        return -1;
    }

    if (client != NULL) {
        if (curl_http_version_is_h3(http_version)) {
            atomic_fetch_add(&client->http3_responses_total, 1);
        } else if (curl_http_version_is_h2(http_version)) {
            atomic_fetch_add(&client->http2_responses_total, 1);
        } else if (curl_http_version_is_h1(http_version)) {
            atomic_fetch_add(&client->http1_responses_total, 1);
        } else {
            atomic_fetch_add(&client->http_other_responses_total, 1);
        }
    }

    *response_out = response.data;
    *response_len_out = response.len;
    return 0;
}

proxy_status_t upstream_doh_client_init(upstream_doh_client_t **client_out, const upstream_config_t *config) {
    if (client_out == NULL || config == NULL) {
        return set_error(PROXY_ERR_INVALID_ARG,
                         "client_out=%p config=%p",
                         (const void *)client_out, (const void *)config);
    }

    upstream_doh_client_t *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return set_error_errno(PROXY_ERR_RESOURCE,
                               "calloc upstream_doh_client_t");
    }

    client->pool_size = config->pool_size > 0 ? config->pool_size : 6;

    CURLcode curl_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_rc != CURLE_OK) {
        free(client);
        return set_error(PROXY_ERR_RESOURCE,
                         "curl_global_init failed (CURLcode=%d)",
                         (int)curl_rc);
    }

    int mtx_rc = pthread_mutex_init(&client->pool_mutex, NULL);
    if (mtx_rc != 0) {
        curl_global_cleanup();
        free(client);
        return set_error(PROXY_ERR_RESOURCE,
                         "pthread_mutex_init failed (rc=%d)",
                         mtx_rc);
    }

    int cond_rc = pthread_cond_init(&client->pool_cond, NULL);
    if (cond_rc != 0) {
        pthread_mutex_destroy(&client->pool_mutex);
        curl_global_cleanup();
        free(client);
        return set_error(PROXY_ERR_RESOURCE,
                         "pthread_cond_init failed (rc=%d)",
                         cond_rc);
    }

    int pool_size = client->pool_size;
    client->pool_handles = calloc((size_t)pool_size, sizeof(*client->pool_handles));
    client->pool_in_use = calloc((size_t)pool_size, sizeof(*client->pool_in_use));
    if (client->pool_handles == NULL || client->pool_in_use == NULL) {
        free(client->pool_handles);
        free(client->pool_in_use);
        pthread_cond_destroy(&client->pool_cond);
        pthread_mutex_destroy(&client->pool_mutex);
        curl_global_cleanup();
        free(client);
        return set_error_errno(PROXY_ERR_RESOURCE,
                               "calloc DoH pool (size=%d)",
                               pool_size);
    }

    for (int i = 0; i < pool_size; i++) {
        client->pool_handles[i] = curl_easy_init();
        if (client->pool_handles[i] == NULL) {
            for (int j = 0; j < i; j++) {
                curl_easy_cleanup(client->pool_handles[j]);
            }
            free(client->pool_handles);
            free(client->pool_in_use);
            pthread_cond_destroy(&client->pool_cond);
            pthread_mutex_destroy(&client->pool_mutex);
            curl_global_cleanup();
            free(client);
            return set_error(PROXY_ERR_RESOURCE,
                             "curl_easy_init failed for pool slot %d/%d",
                             i, pool_size);
        }
    }

    client->initialized = 1;
    *client_out = client;
    return PROXY_OK;
}

void upstream_doh_client_destroy(upstream_doh_client_t *client) {
    if (client == NULL) {
        return;
    }

    if (client->pool_handles != NULL) {
        for (int i = 0; i < client->pool_size; i++) {
            if (client->pool_handles[i] != NULL) {
                curl_easy_cleanup(client->pool_handles[i]);
            }
        }
    }

    free(client->pool_handles);
    free(client->pool_in_use);

    if (client->initialized) {
        pthread_cond_destroy(&client->pool_cond);
        pthread_mutex_destroy(&client->pool_mutex);
        curl_global_cleanup();
    }
    
    free(client);
}

int upstream_doh_resolve(
    upstream_doh_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {

    if (client == NULL || server == NULL || query == NULL || query_len == 0 ||
        response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    if (server->type != UPSTREAM_TYPE_DOH) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_UNKNOWN;

    CURL *curl = NULL;
    int slot = -1;
    if (pool_acquire(client, &curl, &slot) != 0) {
        return -1;
    }
    
    uint8_t *response = NULL;
    size_t response_len = 0;
    doh_attempt_error_t attempt_err;

    uint64_t now = now_ms();
    doh_http_tier_t forced_tier = (doh_http_tier_t)server->stage.doh_forced_http_tier;
    if (forced_tier < DOH_HTTP_TIER_H3 || forced_tier > DOH_HTTP_TIER_H1) {
        forced_tier = DOH_HTTP_TIER_H3;
        server->stage.doh_forced_http_tier = (uint8_t)forced_tier;
    }

    doh_http_tier_t top_tier = forced_tier;
    int attempted_upgrade = 0;
    if (forced_tier > DOH_HTTP_TIER_H3 &&
        now >= server->stage.doh_upgrade_retry_after_ms) {
        top_tier = (doh_http_tier_t)(forced_tier - 1);
        attempted_upgrade = 1;
    }

    int route_count = 1;
    if (server->stage.has_stage1_cached_v4) {
        route_count++;
    }
    if (server->stage.has_bootstrap_v4) {
        route_count++;
    }
    int protocol_attempts_per_route = (int)(DOH_HTTP_TIER_H1 - top_tier + 1);
    int attempts_left = route_count * protocol_attempts_per_route;
    int total_budget_ms = timeout_ms > 0 ? timeout_ms : 1000;
    uint64_t deadline_ms = now + (uint64_t)total_budget_ms;
    int result = -1;
    upstream_failure_class_t final_failure_class = UPSTREAM_FAILURE_CLASS_UNKNOWN;
    doh_http_tier_t successful_tier = DOH_HTTP_TIER_H3;
    int h3_was_attempted = (top_tier == DOH_HTTP_TIER_H3) ? 1 : 0;

    for (int route = 0; route < route_count && result != 0; route++) {
        int use_override_v4 = 0;
        uint32_t override_addr_v4_be = 0;
        const char *phase = "primary request";

        if (route == 1 && server->stage.has_stage1_cached_v4) {
            use_override_v4 = 1;
            override_addr_v4_be = server->stage.stage1_cached_addr_v4_be;
            phase = "stage1 cached IPv4";
        } else if ((route == 1 && !server->stage.has_stage1_cached_v4 && server->stage.has_bootstrap_v4) ||
                   (route == 2 && server->stage.has_bootstrap_v4)) {
            use_override_v4 = 1;
            override_addr_v4_be = server->stage.bootstrap_addr_v4_be;
            phase = "stage2 bootstrap IPv4";
            LOGF_WARN("DoH stage1 local resolver failed, trying stage2 bootstrap IPv4: host=%s", server->host);
        }

        /* Iterate via int so the post-increment past DOH_HTTP_TIER_H1 doesn't
         * temporarily hold an out-of-range enum value (clang-analyzer flags
         * that even though the loop exits before the cast is observed). */
        for (int tier_idx = (int)top_tier; tier_idx <= (int)DOH_HTTP_TIER_H1; tier_idx++) {
            doh_http_tier_t tier = (doh_http_tier_t)tier_idx;
            int attempt_timeout_ms = next_attempt_timeout_ms(deadline_ms, attempts_left > 0 ? attempts_left : 1);
            if (attempt_timeout_ms < 0) {
                pool_release(client, slot);
                server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_TIMEOUT;
                return -1;
            }

            result = doh_post_with_handle(
                client,
                curl,
                server,
                tier,
                use_override_v4,
                override_addr_v4_be,
                attempt_timeout_ms,
                query,
                query_len,
                &response,
                &response_len,
                &attempt_err);
            attempts_left--;

            if (result == 0) {
                successful_tier = tier;
                if (strcmp(phase, "stage2 bootstrap IPv4") == 0) {
                    LOGF_INFO("DoH stage2 bootstrap IPv4 succeeded: host=%s protocol=%s", server->host, doh_tier_name(tier));
                }
                break;
            }

            LOG_DOH_ATTEMPT_FAILURE(phase, server, &attempt_err);
            upstream_failure_class_t attempt_class = doh_failure_class(attempt_err.curl_rc, attempt_err.http_status, attempt_err.response_len);
            if ((int)tier >= 0 && (int)tier < DOH_HTTP_TIER_COUNT &&
                (int)attempt_class >= 0 && (int)attempt_class < UPSTREAM_FAILURE_CLASS_COUNT) {
                __atomic_add_fetch(&server->stage.doh_attempt_failures_total[(int)tier][(int)attempt_class], 1, __ATOMIC_RELAXED);
            }
            final_failure_class = attempt_class;
            server->stage.last_failure_class = (int)final_failure_class;
        }
    }
    
    pool_release(client, slot);
    
    if (result != 0) {
        now = now_ms();
        if (failure_class_is_transport_like(final_failure_class)) {
            server->stage.transport_retry_suppress_until_ms = now + DOH_TRANSPORT_SUPPRESS_MS;
            if (attempted_upgrade) {
                __atomic_add_fetch(&server->stage.doh_upgrade_probe_attempt_total, 1, __ATOMIC_RELAXED);
                __atomic_add_fetch(&server->stage.doh_upgrade_probe_failure_total, 1, __ATOMIC_RELAXED);
                if (server->stage.doh_upgrade_failures < 255) {
                    server->stage.doh_upgrade_failures++;
                }
                server->stage.doh_upgrade_retry_after_ms =
                    now + doh_upgrade_backoff_ms(server->stage.doh_upgrade_failures);
            }
        }
        return -1;
    }
    
    /* Validate response matches query */
    if (dns_validate_response_for_query(query, query_len, response, response_len) != 0) {
        free(response);
        return -1;
    }

    now = now_ms();
    if (h3_was_attempted) {
        if (successful_tier == DOH_HTTP_TIER_H3) {
            server->stage.doh_h3_consecutive_failures = 0;
        } else if (server->stage.doh_h3_consecutive_failures < 255) {
            server->stage.doh_h3_consecutive_failures++;
        }
    }
    int h3_to_h2_pin_gated = (forced_tier == DOH_HTTP_TIER_H3 &&
                              successful_tier == DOH_HTTP_TIER_H2 &&
                              server->stage.doh_h3_consecutive_failures < DOH_DOWNGRADE_H3_CONSECUTIVE_THRESHOLD);
    if (successful_tier > forced_tier && !h3_to_h2_pin_gated) {
        if (forced_tier == DOH_HTTP_TIER_H3 && successful_tier == DOH_HTTP_TIER_H2) {
            __atomic_add_fetch(&server->stage.doh_downgrade_h3_to_h2_total, 1, __ATOMIC_RELAXED);
        } else if (forced_tier == DOH_HTTP_TIER_H3 && successful_tier == DOH_HTTP_TIER_H1) {
            __atomic_add_fetch(&server->stage.doh_downgrade_h3_to_h1_total, 1, __ATOMIC_RELAXED);
        } else if (forced_tier == DOH_HTTP_TIER_H2 && successful_tier == DOH_HTTP_TIER_H1) {
            __atomic_add_fetch(&server->stage.doh_downgrade_h2_to_h1_total, 1, __ATOMIC_RELAXED);
        }
        server->stage.doh_forced_http_tier = (uint8_t)successful_tier;
        if (server->stage.doh_upgrade_failures < 255) {
            server->stage.doh_upgrade_failures++;
        }
        server->stage.doh_upgrade_retry_after_ms =
            now + doh_upgrade_backoff_ms(server->stage.doh_upgrade_failures);
        LOGF_WARN(
            "DoH protocol downgrade pinned: host=%s forced=%s retry_after_ms=%llu failures=%u",
            server->host,
            doh_tier_name(successful_tier),
            (unsigned long long)server->stage.doh_upgrade_retry_after_ms,
            (unsigned)server->stage.doh_upgrade_failures);
    } else if (attempted_upgrade && successful_tier < forced_tier) {
        __atomic_add_fetch(&server->stage.doh_upgrade_probe_attempt_total, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&server->stage.doh_upgrade_probe_success_total, 1, __ATOMIC_RELAXED);
        server->stage.doh_forced_http_tier = (uint8_t)successful_tier;
        server->stage.doh_upgrade_failures = 0;
        server->stage.doh_upgrade_retry_after_ms = now + DOH_UPGRADE_BACKOFF_BASE_MS;
        LOGF_INFO("DoH protocol upgrade accepted: host=%s protocol=%s", server->host, doh_tier_name(successful_tier));
    } else if (attempted_upgrade && successful_tier == forced_tier) {
        __atomic_add_fetch(&server->stage.doh_upgrade_probe_attempt_total, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&server->stage.doh_upgrade_probe_failure_total, 1, __ATOMIC_RELAXED);
        if (server->stage.doh_upgrade_failures < 255) {
            server->stage.doh_upgrade_failures++;
        }
        server->stage.doh_upgrade_retry_after_ms =
            now + doh_upgrade_backoff_ms(server->stage.doh_upgrade_failures);
    }

    server->stage.last_failure_class = UPSTREAM_FAILURE_CLASS_UNKNOWN;
    server->stage.transport_retry_suppress_until_ms = 0;
    
    *response_out = response;
    *response_len_out = response_len;
    return 0;
}

int upstream_doh_client_get_pool_stats(
    upstream_doh_client_t *client,
    int *capacity_out,
    int *in_use_out,
    uint64_t *http3_total_out,
    uint64_t *http2_total_out,
    uint64_t *http1_total_out,
    uint64_t *http_other_total_out) {
    if (capacity_out != NULL) {
        *capacity_out = 0;
    }
    if (in_use_out != NULL) {
        *in_use_out = 0;
    }
    if (http3_total_out != NULL) {
        *http3_total_out = 0;
    }
    if (http2_total_out != NULL) {
        *http2_total_out = 0;
    }
    if (http1_total_out != NULL) {
        *http1_total_out = 0;
    }
    if (http_other_total_out != NULL) {
        *http_other_total_out = 0;
    }

    if (client == NULL) {
        return -1;
    }

    int in_use = 0;
    pthread_mutex_lock(&client->pool_mutex);
    for (int i = 0; i < client->pool_size; i++) {
        if (client->pool_in_use[i]) {
            in_use++;
        }
    }
    pthread_mutex_unlock(&client->pool_mutex);

    if (capacity_out != NULL) {
        *capacity_out = client->pool_size;
    }
    if (in_use_out != NULL) {
        *in_use_out = in_use;
    }
    if (http3_total_out != NULL) {
        *http3_total_out = (uint64_t)atomic_load(&client->http3_responses_total);
    }
    if (http2_total_out != NULL) {
        *http2_total_out = (uint64_t)atomic_load(&client->http2_responses_total);
    }
    if (http1_total_out != NULL) {
        *http1_total_out = (uint64_t)atomic_load(&client->http1_responses_total);
    }
    if (http_other_total_out != NULL) {
        *http_other_total_out = (uint64_t)atomic_load(&client->http_other_responses_total);
    }

    return 0;
}
