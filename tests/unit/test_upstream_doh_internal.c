#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <curl/curl.h>
#include <pthread.h>

#ifdef curl_easy_setopt
#undef curl_easy_setopt
#endif
#ifdef curl_easy_getinfo
#undef curl_easy_getinfo
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "upstream.h"

static upstream_server_t make_test_server(void) {
    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOH;
    strncpy(server.url, "https://x", sizeof(server.url) - 1);
    strncpy(server.host, "x", sizeof(server.host) - 1);
    server.port = 443;
    return server;
}

static CURLcode g_curl_global_init_rc = CURLE_OK;
static int g_curl_easy_init_fail_at = 0;
static int g_curl_easy_init_calls = 0;
static int g_curl_slist_fail_on_call = 0;
static int g_curl_slist_calls = 0;
static CURLcode g_curl_perform_rc = CURLE_OK;
static long g_curl_response_code = 200;
static long g_curl_http_version = 0;
static int g_emit_body = 0;
static const uint8_t *g_body_ptr = NULL;
static size_t g_body_len = 0;
static int g_dns_validate_rc = 0;
static int g_pthread_mutex_init_fail = 0;
static int g_pthread_cond_init_fail = 0;
static int g_calloc_fail_on_call = 0;
static int g_calloc_calls = 0;
static int g_realloc_fail_on_call = 0;
static int g_realloc_calls = 0;
static int g_curl_http_version_setopt_calls = 0;
static long g_curl_http_version_setopt_value = 0;

typedef struct {
    size_t (*write_fn)(char *, size_t, size_t, void *);
    void *write_data;
} curl_slot_t;

static curl_slot_t g_slots[16];

static void reset_stubs(void) {
    g_curl_global_init_rc = CURLE_OK;
    g_curl_easy_init_fail_at = 0;
    g_curl_easy_init_calls = 0;
    g_curl_slist_fail_on_call = 0;
    g_curl_slist_calls = 0;
    g_curl_perform_rc = CURLE_OK;
    g_curl_response_code = 200;
    g_curl_http_version = 0;
    g_emit_body = 0;
    g_body_ptr = NULL;
    g_body_len = 0;
    g_dns_validate_rc = 0;
    g_pthread_mutex_init_fail = 0;
    g_pthread_cond_init_fail = 0;
    g_calloc_fail_on_call = 0;
    g_calloc_calls = 0;
    g_realloc_fail_on_call = 0;
    g_realloc_calls = 0;
    g_curl_http_version_setopt_calls = 0;
    g_curl_http_version_setopt_value = 0;
    memset(g_slots, 0, sizeof(g_slots));
}

static int doh_wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    if (g_pthread_mutex_init_fail) {
        return -1;
    }
    return pthread_mutex_init(mutex, attr);
}

static int doh_wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    if (g_pthread_cond_init_fail) {
        return -1;
    }
    return pthread_cond_init(cond, attr);
}

static void *doh_wrap_calloc(size_t nmemb, size_t size) {
    g_calloc_calls++;
    if (g_calloc_fail_on_call > 0 && g_calloc_calls == g_calloc_fail_on_call) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static void *doh_wrap_realloc(void *ptr, size_t size) {
    g_realloc_calls++;
    if (g_realloc_fail_on_call > 0 && g_realloc_calls == g_realloc_fail_on_call) {
        return NULL;
    }
    return realloc(ptr, size);
}

static size_t curl_slot_index(CURL *handle) {
    uintptr_t v = (uintptr_t)handle;
    size_t idx = (size_t)(v & 0x0Fu);
    return idx;
}

CURLcode curl_global_init(long flags) {
    (void)flags;
    return g_curl_global_init_rc;
}

void curl_global_cleanup(void) {
}

CURL *curl_easy_init(void) {
    g_curl_easy_init_calls++;
    if (g_curl_easy_init_fail_at > 0 && g_curl_easy_init_calls == g_curl_easy_init_fail_at) {
        return NULL;
    }
    return (CURL *)(uintptr_t)(0x10 + g_curl_easy_init_calls);
}

void curl_easy_cleanup(CURL *curl) {
    (void)curl;
}

void curl_easy_reset(CURL *curl) {
    (void)curl;
}

CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...) {
    va_list ap;
    va_start(ap, option);
    size_t idx = curl_slot_index(curl);

    if (option == CURLOPT_WRITEFUNCTION) {
        g_slots[idx].write_fn = va_arg(ap, size_t (*)(char *, size_t, size_t, void *));
    } else if (option == CURLOPT_WRITEDATA) {
        g_slots[idx].write_data = va_arg(ap, void *);
    } else if (option == CURLOPT_HTTP_VERSION) {
        g_curl_http_version_setopt_value = va_arg(ap, long);
        g_curl_http_version_setopt_calls++;
    } else {
        (void)va_arg(ap, void *);
    }

    va_end(ap);
    return CURLE_OK;
}

CURLcode curl_easy_perform(CURL *curl) {
    if (g_emit_body) {
        size_t idx = curl_slot_index(curl);
        if (g_slots[idx].write_fn != NULL && g_body_ptr != NULL && g_body_len > 0) {
            (void)g_slots[idx].write_fn((char *)g_body_ptr, 1, g_body_len, g_slots[idx].write_data);
        }
    }
    return g_curl_perform_rc;
}

CURLcode curl_easy_getinfo(CURL *curl, CURLINFO info, ...) {
    (void)curl;
    va_list ap;
    va_start(ap, info);
    if (info == CURLINFO_RESPONSE_CODE) {
        long *status = va_arg(ap, long *);
        if (status != NULL) {
            *status = g_curl_response_code;
        }
    } else if (info == CURLINFO_HTTP_VERSION) {
        long *version = va_arg(ap, long *);
        if (version != NULL) {
            *version = g_curl_http_version;
        }
    } else {
        (void)va_arg(ap, void *);
    }
    va_end(ap);
    return CURLE_OK;
}

struct curl_slist *curl_slist_append(struct curl_slist *list, const char *data) {
    g_curl_slist_calls++;
    if (g_curl_slist_fail_on_call > 0 && g_curl_slist_calls == g_curl_slist_fail_on_call) {
        return NULL;
    }

    struct curl_slist *node = malloc(sizeof(*node));
    if (node == NULL) {
        return NULL;
    }
    node->data = strdup(data);
    node->next = NULL;

    if (list == NULL) {
        return node;
    }

    struct curl_slist *tail = list;
    while (tail->next != NULL) {
        tail = tail->next;
    }
    tail->next = node;
    return list;
}

void curl_slist_free_all(struct curl_slist *list) {
    while (list != NULL) {
        struct curl_slist *next = list->next;
        free(list->data);
        free(list);
        list = next;
    }
}

int dns_validate_response_for_query(const uint8_t *query, size_t query_len, const uint8_t *response, size_t response_len) {
    (void)query;
    (void)query_len;
    (void)response;
    (void)response_len;
    return g_dns_validate_rc;
}

#define pthread_mutex_init doh_wrap_pthread_mutex_init
#define pthread_cond_init doh_wrap_pthread_cond_init
#define calloc doh_wrap_calloc
#define realloc doh_wrap_realloc
#include "../../src/upstream_doh.c"
#undef realloc
#undef calloc
#undef pthread_cond_init
#undef pthread_mutex_init

static void test_write_callback_growth(void **state) {
    (void)state;
    reset_stubs();

    buffer_t b = {0};
    const char chunk1[] = "abc";
    const char chunk2[] = "defg";

    assert_int_equal((int)write_callback((char *)chunk1, 1, 3, &b), 3);
    assert_int_equal((int)write_callback((char *)chunk2, 1, 4, &b), 4);
    assert_int_equal((int)b.len, 7);
    assert_memory_equal(b.data, "abcdefg", 7);

    free(b.data);
}

static void test_write_callback_realloc_failure(void **state) {
    (void)state;
    reset_stubs();

    buffer_t b = {0};
    const char chunk[] = "abcdef";
    g_realloc_fail_on_call = 1;
    assert_int_equal((int)write_callback((char *)chunk, 1, sizeof(chunk) - 1, &b), 0);
    assert_null(b.data);
    assert_int_equal((int)b.len, 0);
}

typedef struct {
    upstream_doh_client_t *client;
    CURL *handle;
    int slot;
    int rc;
} acquire_ctx_t;

static void *pool_acquire_thread_main(void *arg) {
    acquire_ctx_t *ctx = (acquire_ctx_t *)arg;
    ctx->rc = pool_acquire(ctx->client, &ctx->handle, &ctx->slot);
    return NULL;
}

static void test_pool_acquire_wait_and_release_path(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_doh_client_t *client = NULL;
    assert_int_equal(upstream_doh_client_init(&client, &config), 0);
    assert_non_null(client);

    client->pool_in_use[0] = 1;

    acquire_ctx_t actx;
    memset(&actx, 0, sizeof(actx));
    actx.client = client;
    actx.slot = -1;
    actx.rc = -1;

    pthread_t t;
    assert_int_equal(pthread_create(&t, NULL, pool_acquire_thread_main, &actx), 0);

    struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
    nanosleep(&ts, NULL);
    pool_release(client, 0);

    pthread_join(t, NULL);
    assert_int_equal(actx.rc, 0);
    assert_int_equal(actx.slot, 0);
    assert_non_null(actx.handle);

    pool_release(client, actx.slot);
    upstream_doh_client_destroy(client);
}

static void test_doh_post_header_failures(void **state) {
    (void)state;
    reset_stubs();
    upstream_server_t server = make_test_server();

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    uint8_t query[2] = {0x12, 0x34};

    g_curl_slist_fail_on_call = 1;
    assert_int_equal(doh_post_with_handle(NULL, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), -1);

    reset_stubs();
    g_curl_slist_fail_on_call = 2;
    assert_int_equal(doh_post_with_handle(NULL, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), -1);
}

static void test_doh_post_transport_and_status_failures(void **state) {
    (void)state;
    reset_stubs();
    upstream_server_t server = make_test_server();

    upstream_doh_client_t client;
    memset(&client, 0, sizeof(client));

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    uint8_t query[2] = {0x12, 0x34};

    g_curl_perform_rc = CURLE_COULDNT_CONNECT;
    g_curl_http_version = 9999;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal((uint64_t)atomic_load(&client.http_other_responses_total), 0);

    reset_stubs();
    memset(&client, 0, sizeof(client));
    g_curl_response_code = 503;
    g_curl_http_version = 9999;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal((uint64_t)atomic_load(&client.http_other_responses_total), 0);

    reset_stubs();
    memset(&client, 0, sizeof(client));
    g_curl_http_version = 9999;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), -1);
    assert_int_equal((uint64_t)atomic_load(&client.http_other_responses_total), 0);
}

static void test_doh_post_success_and_http_version_counters(void **state) {
    (void)state;
    reset_stubs();
    upstream_server_t server = make_test_server();

    upstream_doh_client_t client;
    memset(&client, 0, sizeof(client));

    uint8_t query[2] = {0x12, 0x34};
    const uint8_t body[] = {0x12, 0x34, 0x81, 0x80};
    g_emit_body = 1;
    g_body_ptr = body;
    g_body_len = sizeof(body);

    uint8_t *resp = NULL;
    size_t resp_len = 0;

#if defined(CURL_HTTP_VERSION_3)
    g_curl_http_version = CURL_HTTP_VERSION_3;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x12, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    free(resp);
#elif defined(CURL_HTTP_VERSION_3ONLY)
    g_curl_http_version = CURL_HTTP_VERSION_3ONLY;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x12, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    free(resp);
#endif

#ifdef CURL_HTTP_VERSION_2_0
    g_curl_http_version = CURL_HTTP_VERSION_2_0;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x12, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    free(resp);
#endif

#ifdef CURL_HTTP_VERSION_1_1
    resp = NULL;
    g_curl_http_version = CURL_HTTP_VERSION_1_1;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x12, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    free(resp);
#endif

    resp = NULL;
    g_curl_http_version = 9999;
    assert_int_equal(doh_post_with_handle(&client, (CURL *)0x12, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    assert_non_null(resp);
    assert_int_equal((int)resp_len, (int)sizeof(body));
    free(resp);

    assert_true((uint64_t)atomic_load(&client.http_other_responses_total) >= 1);
}

static void test_doh_post_http_version_preference(void **state) {
    (void)state;
    reset_stubs();
    upstream_server_t server = make_test_server();

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    uint8_t query[2] = {0x12, 0x34};
    const uint8_t body[] = {0x12, 0x34, 0x81, 0x80};
    g_emit_body = 1;
    g_body_ptr = body;
    g_body_len = sizeof(body);

    assert_int_equal(doh_post_with_handle(NULL, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    free(resp);
    assert_true(g_curl_http_version_setopt_calls >= 1);

#ifdef CURL_HTTP_VERSION_3
    assert_int_equal(g_curl_http_version_setopt_value, CURL_HTTP_VERSION_3);
#elif defined(CURL_HTTP_VERSION_3ONLY)
    assert_int_equal(g_curl_http_version_setopt_value, CURL_HTTP_VERSION_3ONLY);
#elif defined(CURL_HTTP_VERSION_2TLS)
    assert_int_equal(g_curl_http_version_setopt_value, CURL_HTTP_VERSION_2TLS);
#elif defined(CURL_HTTP_VERSION_2)
    assert_int_equal(g_curl_http_version_setopt_value, CURL_HTTP_VERSION_2);
#else
    assert_int_equal(g_curl_http_version_setopt_value, CURL_HTTP_VERSION_NONE);
#endif

    setenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1", "1", 1);
    reset_stubs();
    g_emit_body = 1;
    g_body_ptr = body;
    g_body_len = sizeof(body);
    resp = NULL;
    assert_int_equal(doh_post_with_handle(NULL, (CURL *)0x11, &server, 0, 100, query, sizeof(query), &resp, &resp_len), 0);
    free(resp);
    assert_true(g_curl_http_version_setopt_calls >= 1);
#ifdef CURL_HTTP_VERSION_1_1
    assert_int_equal(g_curl_http_version_setopt_value, CURL_HTTP_VERSION_1_1);
#endif
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1");
}

static void test_doh_client_init_failure_paths(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 2,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };

    upstream_doh_client_t *client = NULL;

    g_calloc_fail_on_call = 1;
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);

    reset_stubs();

    g_curl_global_init_rc = CURLE_FAILED_INIT;
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);

    reset_stubs();
    g_curl_easy_init_fail_at = 2;
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);

    reset_stubs();
    g_pthread_mutex_init_fail = 1;
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);

    reset_stubs();
    g_pthread_cond_init_fail = 1;
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);

    reset_stubs();
    g_calloc_fail_on_call = 2; /* pool_handles alloc */
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);

    reset_stubs();
    g_calloc_fail_on_call = 3; /* pool_in_use alloc */
    assert_int_equal(upstream_doh_client_init(&client, &config), -1);
}

static void test_doh_resolve_success_and_validation_failure(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_doh_client_t *client = NULL;
    assert_int_equal(upstream_doh_client_init(&client, &config), 0);

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOH;
    strcpy(server.url, "https://example.test/dns-query");

    uint8_t query[2] = {0x12, 0x34};
    const uint8_t body[] = {0x12, 0x34, 0x81, 0x80};
    g_emit_body = 1;
    g_body_ptr = body;
    g_body_len = sizeof(body);

    uint8_t *resp = NULL;
    size_t resp_len = 0;

    g_dns_validate_rc = -1;
    assert_int_equal(upstream_doh_resolve(client, &server, 50, query, sizeof(query), &resp, &resp_len), -1);

    g_dns_validate_rc = 0;
    assert_int_equal(upstream_doh_resolve(client, &server, 50, query, sizeof(query), &resp, &resp_len), 0);
    assert_non_null(resp);
    free(resp);

    upstream_doh_client_destroy(client);
}

static void test_doh_pool_stats_in_use_branch(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t config = {
        .timeout_ms = 100,
        .pool_size = 2,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_doh_client_t *client = NULL;
    assert_int_equal(upstream_doh_client_init(&client, &config), 0);
    assert_non_null(client);

    client->pool_in_use[0] = 1;

    int cap = 0;
    int in_use = 0;
    uint64_t h3 = 0;
    uint64_t h2 = 0;
    uint64_t h1 = 0;
    uint64_t other = 0;
    assert_int_equal(upstream_doh_client_get_pool_stats(client, &cap, &in_use, &h3, &h2, &h1, &other), 0);
    assert_int_equal(cap, 2);
    assert_int_equal(in_use, 1);

    upstream_doh_client_destroy(client);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_write_callback_growth),
        cmocka_unit_test(test_write_callback_realloc_failure),
        cmocka_unit_test(test_pool_acquire_wait_and_release_path),
        cmocka_unit_test(test_doh_post_header_failures),
        cmocka_unit_test(test_doh_post_transport_and_status_failures),
        cmocka_unit_test(test_doh_post_success_and_http_version_counters),
        cmocka_unit_test(test_doh_post_http_version_preference),
        cmocka_unit_test(test_doh_client_init_failure_paths),
        cmocka_unit_test(test_doh_resolve_success_and_validation_failure),
        cmocka_unit_test(test_doh_pool_stats_in_use_branch),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
