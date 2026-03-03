#include "upstream.h"
#include "dns_message.h"
#include "logger.h"

#include <curl/curl.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>

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
    int used_override_v4;
    uint32_t override_addr_v4_be;
} doh_attempt_error_t;

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

static void log_doh_attempt_failure(const char *phase, const upstream_server_t *server, const doh_attempt_error_t *err) {
    if (phase == NULL || server == NULL || err == NULL) {
        return;
    }

    char ip_text[INET_ADDRSTRLEN];
    ip_text[0] = '\0';
    if (err->used_override_v4) {
        format_ipv4(err->override_addr_v4_be, ip_text, sizeof(ip_text));
    }

    const char *reason = doh_failure_reason(err->curl_rc, err->http_status, err->response_len);
    LOGF_WARN(
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
}

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
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, doh_preferred_http_version());
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

int upstream_doh_client_init(upstream_doh_client_t **client_out, const upstream_config_t *config) {
    if (client_out == NULL || config == NULL) {
        return -1;
    }
    
    upstream_doh_client_t *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return -1;
    }
    
    client->pool_size = config->pool_size > 0 ? config->pool_size : 6;
    
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        free(client);
        return -1;
    }

    if (pthread_mutex_init(&client->pool_mutex, NULL) != 0) {
        curl_global_cleanup();
        free(client);
        return -1;
    }

    if (pthread_cond_init(&client->pool_cond, NULL) != 0) {
        pthread_mutex_destroy(&client->pool_mutex);
        curl_global_cleanup();
        free(client);
        return -1;
    }

    client->pool_handles = calloc((size_t)client->pool_size, sizeof(*client->pool_handles));
    client->pool_in_use = calloc((size_t)client->pool_size, sizeof(*client->pool_in_use));
    if (client->pool_handles == NULL || client->pool_in_use == NULL) {
        free(client->pool_handles);
        free(client->pool_in_use);
        pthread_cond_destroy(&client->pool_cond);
        pthread_mutex_destroy(&client->pool_mutex);
        curl_global_cleanup();
        free(client);
        return -1;
    }

    for (int i = 0; i < client->pool_size; i++) {
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
            return -1;
        }
    }

    client->initialized = 1;
    *client_out = client;
    return 0;
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
    const upstream_server_t *server,
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
    
    CURL *curl = NULL;
    int slot = -1;
    if (pool_acquire(client, &curl, &slot) != 0) {
        return -1;
    }
    
    uint8_t *response = NULL;
    size_t response_len = 0;
    doh_attempt_error_t attempt_err;
    
    int result = doh_post_with_handle(
        client,
        curl,
        server,
        0,
        0,
        timeout_ms,
        query, query_len,
        &response, &response_len,
        &attempt_err);

    if (result != 0) {
        log_doh_attempt_failure("primary request", server, &attempt_err);
    }

    if (result != 0 && server->stage.has_stage1_cached_v4) {
        result = doh_post_with_handle(
            client,
            curl,
            server,
            1,
            server->stage.stage1_cached_addr_v4_be,
            timeout_ms,
            query,
            query_len,
            &response,
            &response_len,
            &attempt_err);
        if (result != 0) {
            log_doh_attempt_failure("stage1 cached IPv4", server, &attempt_err);
        }
    }

    if (result != 0 && server->stage.has_bootstrap_v4) {
        /*
         * Stage 2 fallback: pin host:port to bootstrap IP for this request.
         * We still keep the original hostname for SNI/cert checks.
         *
         * Not the default path: local DNS is usually fresher when providers
         * rotate or rebalance endpoints.
         */
        LOGF_WARN("DoH stage1 local resolver failed, trying stage2 bootstrap IPv4: host=%s", server->host);
        result = doh_post_with_handle(
            client,
            curl,
            server,
            1,
            server->stage.bootstrap_addr_v4_be,
            timeout_ms,
            query,
            query_len,
            &response,
            &response_len,
            &attempt_err);
        if (result == 0) {
            LOGF_INFO("DoH stage2 bootstrap IPv4 succeeded: host=%s", server->host);
        } else {
            log_doh_attempt_failure("stage2 bootstrap IPv4", server, &attempt_err);
        }
    }
    
    pool_release(client, slot);
    
    if (result != 0) {
        return -1;
    }
    
    /* Validate response matches query */
    if (dns_validate_response_for_query(query, query_len, response, response_len) != 0) {
        free(response);
        return -1;
    }
    
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
