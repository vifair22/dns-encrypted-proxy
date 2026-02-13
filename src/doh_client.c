#include "doh_client.h"
#include "dns_message.h"

#include <curl/curl.h>

#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} buffer_t;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    buffer_t *buffer = (buffer_t *)userdata;
    size_t chunk = size * nmemb;

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

static int doh_post_with_handle(
    CURL *curl,
    const char *url,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
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
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)query_len);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)timeout_ms);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DOH-Proxy/0.1");

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);

    if (rc != CURLE_OK || status != 200 || response.len == 0) {
        free(response.data);
        return -1;
    }

    *response_out = response.data;
    *response_len_out = response.len;
    return 0;
}

static int pool_acquire(doh_client_t *client, CURL **handle_out, int *slot_out) {
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

static void pool_release(doh_client_t *client, int slot) {
    pthread_mutex_lock(&client->pool_mutex);
    client->pool_in_use[slot] = 0;
    pthread_cond_signal(&client->pool_cond);
    pthread_mutex_unlock(&client->pool_mutex);
}

int doh_client_init(doh_client_t *client, const proxy_config_t *config) {
    if (client == NULL || config == NULL || config->upstream_count <= 0 || config->doh_pool_size <= 0) {
        return -1;
    }

    memset(client, 0, sizeof(*client));
    client->url_count = config->upstream_count;
    client->timeout_ms = config->upstream_timeout_ms;
    client->pool_size = config->doh_pool_size;

    for (int i = 0; i < config->upstream_count; i++) {
        strncpy(client->urls[i], config->upstream_urls[i], MAX_URL_LEN - 1);
        client->urls[i][MAX_URL_LEN - 1] = '\0';
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return -1;
    }

    if (pthread_mutex_init(&client->rr_mutex, NULL) != 0) {
        curl_global_cleanup();
        return -1;
    }

    if (pthread_mutex_init(&client->pool_mutex, NULL) != 0) {
        pthread_mutex_destroy(&client->rr_mutex);
        curl_global_cleanup();
        return -1;
    }

    if (pthread_cond_init(&client->pool_cond, NULL) != 0) {
        pthread_mutex_destroy(&client->pool_mutex);
        pthread_mutex_destroy(&client->rr_mutex);
        curl_global_cleanup();
        return -1;
    }

    client->pool_handles = calloc((size_t)client->pool_size, sizeof(*client->pool_handles));
    client->pool_in_use = calloc((size_t)client->pool_size, sizeof(*client->pool_in_use));
    if (client->pool_handles == NULL || client->pool_in_use == NULL) {
        free(client->pool_handles);
        free(client->pool_in_use);
        pthread_cond_destroy(&client->pool_cond);
        pthread_mutex_destroy(&client->pool_mutex);
        pthread_mutex_destroy(&client->rr_mutex);
        curl_global_cleanup();
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
            pthread_mutex_destroy(&client->rr_mutex);
            curl_global_cleanup();
            return -1;
        }
    }

    return 0;
}

void doh_client_destroy(doh_client_t *client) {
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

    pthread_cond_destroy(&client->pool_cond);
    pthread_mutex_destroy(&client->pool_mutex);
    pthread_mutex_destroy(&client->rr_mutex);

    curl_global_cleanup();
    memset(client, 0, sizeof(*client));
}

int doh_client_resolve(
    doh_client_t *client,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out,
    const char **used_url_out) {
    if (client == NULL || query == NULL || query_len == 0 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    pthread_mutex_lock(&client->rr_mutex);
    uint64_t start = client->next_index;
    client->next_index++;
    pthread_mutex_unlock(&client->rr_mutex);

    CURL *curl = NULL;
    int slot = -1;
    if (pool_acquire(client, &curl, &slot) != 0) {
        return -1;
    }

    for (int attempt = 0; attempt < client->url_count; attempt++) {
        int idx = (int)((start + (uint64_t)attempt) % (uint64_t)client->url_count);

        uint8_t *response = NULL;
        size_t response_len = 0;
        if (doh_post_with_handle(curl, client->urls[idx], client->timeout_ms, query, query_len, &response, &response_len) == 0) {
            if (dns_validate_response_for_query(query, query_len, response, response_len) != 0) {
                free(response);
                continue;
            }

            *response_out = response;
            *response_len_out = response_len;
            if (used_url_out != NULL) {
                *used_url_out = client->urls[idx];
            }
            pool_release(client, slot);
            return 0;
        }
    }

    pool_release(client, slot);
    return -1;
}
