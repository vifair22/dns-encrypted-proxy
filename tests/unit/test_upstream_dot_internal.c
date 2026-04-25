#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

/*
 * OpenSSL 3.x exposes several legacy SSL APIs as macros. This test remaps
 * those symbols to local stubs before including upstream_dot.c, so undefine
 * the OpenSSL macro aliases first to avoid macro redefinition warnings/errors
 * when builds enable -Werror.
 */
#ifdef SSL_library_init
#undef SSL_library_init
#endif
#ifdef SSL_load_error_strings
#undef SSL_load_error_strings
#endif
#ifdef OpenSSL_add_all_algorithms
#undef OpenSSL_add_all_algorithms
#endif
#ifdef SSL_CTX_set_min_proto_version
#undef SSL_CTX_set_min_proto_version
#endif
#ifdef SSL_set_tlsext_host_name
#undef SSL_set_tlsext_host_name
#endif

#include "upstream.h"
#include "dns_message.h"
#include "logger.h"

static int g_getaddrinfo_rc = 0;
static int g_socket_fd = 42;
static int g_fcntl_getfl_rc = 0;
static int g_fcntl_setfl_rc = 0;
static int g_connect_rc = -1;
static int g_connect_errno = EINPROGRESS;
static int g_poll_rc = 1;
static short g_poll_revents = POLLOUT;
static int g_getsockopt_rc = 0;
static int g_getsockopt_error = 0;
static int g_close_calls = 0;

static SSL_CTX *g_ssl_ctx_value = (SSL_CTX *)(uintptr_t)0x101;
static int g_ssl_default_verify_paths_rc = 1;
static int g_ssl_new_fail = 0;
static int g_ssl_connect_rc = 1;
static int g_ssl_get_fd = 42;
static int g_ssl_shutdown_calls = 0;
static int g_ssl_free_calls = 0;

static int g_ssl_read_script[8];
static int g_ssl_read_script_len = 0;
static int g_ssl_read_script_idx = 0;
static const uint8_t *g_ssl_read_data = NULL;
static size_t g_ssl_read_data_len = 0;
static size_t g_ssl_read_data_off = 0;

static int g_ssl_write_script[8];
static int g_ssl_write_script_len = 0;
static int g_ssl_write_script_idx = 0;

static int g_dns_validate_rc = 0;
static int g_pthread_mutex_init_fail = 0;
static int g_pthread_cond_init_fail = 0;
static int g_calloc_fail_on_call = 0;
static int g_calloc_calls = 0;
static int g_malloc_fail_on_call = 0;
static int g_malloc_calls = 0;

static struct sockaddr_in g_addr;
static struct addrinfo g_ai;

static void reset_stubs(void) {
    g_getaddrinfo_rc = 0;
    g_socket_fd = 42;
    g_fcntl_getfl_rc = 0;
    g_fcntl_setfl_rc = 0;
    g_connect_rc = -1;
    g_connect_errno = EINPROGRESS;
    g_poll_rc = 1;
    g_poll_revents = POLLOUT;
    g_getsockopt_rc = 0;
    g_getsockopt_error = 0;
    g_close_calls = 0;

    g_ssl_ctx_value = (SSL_CTX *)(uintptr_t)0x101;
    g_ssl_default_verify_paths_rc = 1;
    g_ssl_new_fail = 0;
    g_ssl_connect_rc = 1;
    g_ssl_get_fd = 42;
    g_ssl_shutdown_calls = 0;
    g_ssl_free_calls = 0;

    g_ssl_read_script_len = 0;
    g_ssl_read_script_idx = 0;
    g_ssl_read_data = NULL;
    g_ssl_read_data_len = 0;
    g_ssl_read_data_off = 0;

    g_ssl_write_script_len = 0;
    g_ssl_write_script_idx = 0;

    g_dns_validate_rc = 0;
    g_pthread_mutex_init_fail = 0;
    g_pthread_cond_init_fail = 0;
    g_calloc_fail_on_call = 0;
    g_calloc_calls = 0;
    g_malloc_fail_on_call = 0;
    g_malloc_calls = 0;

    memset(&g_addr, 0, sizeof(g_addr));
    g_addr.sin_family = AF_INET;
    g_addr.sin_port = htons(853);
    g_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(&g_ai, 0, sizeof(g_ai));
    g_ai.ai_family = AF_INET;
    g_ai.ai_socktype = SOCK_STREAM;
    g_ai.ai_protocol = IPPROTO_TCP;
    g_ai.ai_addrlen = sizeof(g_addr);
    g_ai.ai_addr = (struct sockaddr *)&g_addr;
}

static int dot_wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    if (g_pthread_mutex_init_fail) {
        return -1;
    }
    return pthread_mutex_init(mutex, attr);
}

static int dot_wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    if (g_pthread_cond_init_fail) {
        return -1;
    }
    return pthread_cond_init(cond, attr);
}

static void *dot_wrap_calloc(size_t nmemb, size_t size) {
    g_calloc_calls++;
    if (g_calloc_fail_on_call > 0 && g_calloc_calls == g_calloc_fail_on_call) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static void *dot_wrap_malloc(size_t size) {
    g_malloc_calls++;
    if (g_malloc_fail_on_call > 0 && g_malloc_calls == g_malloc_fail_on_call) {
        return NULL;
    }
    return malloc(size);
}

static int dot_test_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    (void)node;
    (void)service;
    (void)hints;
    if (g_getaddrinfo_rc != 0) {
        return g_getaddrinfo_rc;
    }
    *res = &g_ai;
    return 0;
}

static void dot_test_freeaddrinfo(struct addrinfo *res) {
    (void)res;
}

static int dot_test_socket(int domain, int type, int protocol) {
    (void)domain;
    (void)type;
    (void)protocol;
    return g_socket_fd;
}

static int dot_test_fcntl(int fd, int cmd, ...) {
    (void)fd;
    va_list ap;
    va_start(ap, cmd);
    if (cmd == F_GETFL) {
        va_end(ap);
        return g_fcntl_getfl_rc;
    }
    (void)va_arg(ap, int);
    va_end(ap);
    return g_fcntl_setfl_rc;
}

static int dot_test_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd;
    (void)addr;
    (void)addrlen;
    errno = g_connect_errno;
    return g_connect_rc;
}

static int dot_test_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    (void)timeout;
    if (nfds > 0) {
        fds[0].revents = g_poll_revents;
    }
    return g_poll_rc;
}

static int dot_test_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    (void)sockfd;
    (void)level;
    (void)optname;
    if (g_getsockopt_rc == 0 && optval != NULL && optlen != NULL && *optlen >= sizeof(int)) {
        *(int *)optval = g_getsockopt_error;
    }
    return g_getsockopt_rc;
}

static int dot_test_close(int fd) {
    (void)fd;
    g_close_calls++;
    return 0;
}

static const SSL_METHOD *dot_test_TLS_client_method(void) {
    return (const SSL_METHOD *)(uintptr_t)0x11;
}

static int dot_test_SSL_library_init(void) {
    return 1;
}

static void dot_test_SSL_load_error_strings(void) {
}

static void dot_test_OpenSSL_add_all_algorithms(void) {
}

static SSL_CTX *dot_test_SSL_CTX_new(const SSL_METHOD *meth) {
    (void)meth;
    return g_ssl_ctx_value;
}

static void dot_test_SSL_CTX_free(SSL_CTX *ctx) {
    (void)ctx;
}

static int dot_test_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
    (void)ctx;
    return g_ssl_default_verify_paths_rc;
}

static int dot_test_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version) {
    (void)ctx;
    (void)version;
    return 1;
}

static void dot_test_SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*cb)(int, X509_STORE_CTX *)) {
    (void)ctx;
    (void)mode;
    (void)cb;
}

static SSL *dot_test_SSL_new(SSL_CTX *ctx) {
    (void)ctx;
    if (g_ssl_new_fail) {
        return NULL;
    }
    return (SSL *)(uintptr_t)0x21;
}

static void dot_test_SSL_free(SSL *ssl) {
    (void)ssl;
    g_ssl_free_calls++;
}

static int dot_test_SSL_shutdown(SSL *ssl) {
    (void)ssl;
    g_ssl_shutdown_calls++;
    return 1;
}

static int dot_test_SSL_set_tlsext_host_name(SSL *ssl, const char *name) {
    (void)ssl;
    (void)name;
    return 1;
}

static int dot_test_SSL_set1_host(SSL *ssl, const char *hostname) {
    (void)ssl;
    (void)hostname;
    return 1;
}

static int dot_test_SSL_set_fd(SSL *ssl, int fd) {
    (void)ssl;
    (void)fd;
    return 1;
}

static int dot_test_SSL_connect(SSL *ssl) {
    (void)ssl;
    return g_ssl_connect_rc;
}

static int dot_test_SSL_get_fd(const SSL *ssl) {
    (void)ssl;
    return g_ssl_get_fd;
}

static int dot_test_SSL_read(SSL *ssl, void *buf, int num) {
    (void)ssl;
    if (g_ssl_read_script_idx < g_ssl_read_script_len) {
        int step = g_ssl_read_script[g_ssl_read_script_idx++];
        if (step <= 0) {
            return step;
        }
        int n = step;
        if ((size_t)n > g_ssl_read_data_len - g_ssl_read_data_off) {
            n = (int)(g_ssl_read_data_len - g_ssl_read_data_off);
        }
        if (n > num) {
            n = num;
        }
        if (n > 0 && g_ssl_read_data != NULL) {
            memcpy(buf, g_ssl_read_data + g_ssl_read_data_off, (size_t)n);
            g_ssl_read_data_off += (size_t)n;
        }
        return n;
    }
    return -1;
}

static int dot_test_SSL_write(SSL *ssl, const void *buf, int num) {
    (void)ssl;
    (void)buf;
    if (g_ssl_write_script_idx < g_ssl_write_script_len) {
        int step = g_ssl_write_script[g_ssl_write_script_idx++];
        if (step <= 0) {
            return step;
        }
        return step > num ? num : step;
    }
    return -1;
}

int dns_validate_response_for_query(const uint8_t *query, size_t query_len, const uint8_t *response, size_t response_len) {
    (void)query;
    (void)query_len;
    (void)response;
    (void)response_len;
    return g_dns_validate_rc;
}

void logger_logf(const char *func, const char *level, const char *fmt, ...) {
    (void)func;
    (void)level;
    (void)fmt;
}

#define getaddrinfo dot_test_getaddrinfo
#define freeaddrinfo dot_test_freeaddrinfo
#define socket dot_test_socket
#define fcntl dot_test_fcntl
#define connect dot_test_connect
#define poll dot_test_poll
#define getsockopt dot_test_getsockopt
#define close dot_test_close
#define TLS_client_method dot_test_TLS_client_method
#define SSL_library_init dot_test_SSL_library_init
#define SSL_load_error_strings dot_test_SSL_load_error_strings
#define OpenSSL_add_all_algorithms dot_test_OpenSSL_add_all_algorithms
#define SSL_CTX_new dot_test_SSL_CTX_new
#define SSL_CTX_free dot_test_SSL_CTX_free
#define SSL_CTX_set_default_verify_paths dot_test_SSL_CTX_set_default_verify_paths
#define SSL_CTX_set_min_proto_version dot_test_SSL_CTX_set_min_proto_version
#define SSL_CTX_set_verify dot_test_SSL_CTX_set_verify
#define SSL_new dot_test_SSL_new
#define SSL_free dot_test_SSL_free
#define SSL_shutdown dot_test_SSL_shutdown
#define SSL_set_tlsext_host_name dot_test_SSL_set_tlsext_host_name
#define SSL_set1_host dot_test_SSL_set1_host
#define SSL_set_fd dot_test_SSL_set_fd
#define SSL_connect dot_test_SSL_connect
#define SSL_get_fd dot_test_SSL_get_fd
#define SSL_read dot_test_SSL_read
#define SSL_write dot_test_SSL_write
#define pthread_mutex_init dot_wrap_pthread_mutex_init
#define pthread_cond_init dot_wrap_pthread_cond_init
#define calloc dot_wrap_calloc
#define malloc dot_wrap_malloc

#include "../../src/upstream_dot.c"

#undef malloc
#undef calloc
#undef pthread_cond_init
#undef pthread_mutex_init
#undef SSL_write
#undef SSL_read
#undef SSL_get_fd
#undef SSL_connect
#undef SSL_set_fd
#undef SSL_set1_host
#undef SSL_set_tlsext_host_name
#undef SSL_shutdown
#undef SSL_free
#undef SSL_new
#undef SSL_CTX_set_verify
#undef SSL_CTX_set_min_proto_version
#undef SSL_CTX_set_default_verify_paths
#undef SSL_CTX_free
#undef SSL_CTX_new
#undef OpenSSL_add_all_algorithms
#undef SSL_load_error_strings
#undef SSL_library_init
#undef TLS_client_method
#undef close
#undef getsockopt
#undef poll
#undef connect
#undef fcntl
#undef socket
#undef freeaddrinfo
#undef getaddrinfo

static void test_connect_with_timeout_edge_paths(void **state) {
    (void)state;
    reset_stubs();

    g_getaddrinfo_rc = EAI_FAIL;
    assert_int_equal(connect_with_timeout("x", 853, 10), -1);

    reset_stubs();
    g_socket_fd = -1;
    assert_int_equal(connect_with_timeout("x", 853, 10), -1);

    reset_stubs();
    g_fcntl_getfl_rc = -1;
    assert_int_equal(connect_with_timeout("x", 853, 10), -1);

    reset_stubs();
    g_connect_rc = 0;
    assert_int_equal(connect_with_timeout("x", 853, 10), 42);

    reset_stubs();
    g_connect_rc = -1;
    g_connect_errno = ECONNREFUSED;
    assert_int_equal(connect_with_timeout("x", 853, 10), -1);

    reset_stubs();
    g_poll_rc = 0;
    assert_int_equal(connect_with_timeout("x", 853, 10), -1);

    reset_stubs();
    g_getsockopt_error = EIO;
    assert_int_equal(connect_with_timeout("x", 853, 10), -1);
}

static void test_ssl_io_helpers(void **state) {
    (void)state;
    reset_stubs();

    const uint8_t inbuf[] = {0xAA, 0xBB, 0xCC, 0xDD};
    g_ssl_read_data = inbuf;
    g_ssl_read_data_len = sizeof(inbuf);
    g_ssl_read_script[0] = 2;
    g_ssl_read_script[1] = 2;
    g_ssl_read_script_len = 2;

    uint8_t out[4] = {0};
    assert_int_equal(ssl_read_all((SSL *)(uintptr_t)0x21, out, sizeof(out), 10), 0);
    assert_memory_equal(out, inbuf, sizeof(inbuf));

    reset_stubs();
    g_poll_rc = -1;
    assert_int_equal(ssl_read_all((SSL *)(uintptr_t)0x21, out, 1, 10), -1);

    reset_stubs();
    g_poll_rc = 1;
    g_poll_revents = POLLERR;
    assert_int_equal(ssl_read_all((SSL *)(uintptr_t)0x21, out, 1, 10), -1);

    reset_stubs();
    g_ssl_write_script[0] = 1;
    g_ssl_write_script[1] = 3;
    g_ssl_write_script_len = 2;
    const uint8_t sendbuf[] = {1, 2, 3, 4};
    assert_int_equal(ssl_write_all((SSL *)(uintptr_t)0x21, sendbuf, sizeof(sendbuf)), 0);

    reset_stubs();
    g_ssl_write_script[0] = -1;
    g_ssl_write_script_len = 1;
    assert_int_equal(ssl_write_all((SSL *)(uintptr_t)0x21, sendbuf, sizeof(sendbuf)), -1);
}

static void test_dot_client_init_failure_paths(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t cfg = {
        .timeout_ms = 100,
        .pool_size = 2,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    upstream_dot_client_t *client = NULL;

    g_ssl_ctx_value = NULL;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), -1);

    reset_stubs();
    g_ssl_default_verify_paths_rc = 0;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), -1);

    reset_stubs();
    g_pthread_mutex_init_fail = 1;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), -1);

    reset_stubs();
    g_pthread_cond_init_fail = 1;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), -1);

    reset_stubs();
    g_calloc_fail_on_call = 1;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), -1);

    reset_stubs();
    g_calloc_fail_on_call = 2;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), -1);
}

static void test_establish_tls_connection_paths(void **state) {
    (void)state;
    reset_stubs();

    upstream_dot_client_t client;
    memset(&client, 0, sizeof(client));
    client.ssl_ctx = (SSL_CTX *)(uintptr_t)0x101;

    dot_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = -1;

    g_getaddrinfo_rc = EAI_FAIL;
    assert_int_equal(establish_tls_connection(&client, &conn, "h", 853, 10, 0, 0, NULL), -1);

    reset_stubs();
    memset(&conn, 0, sizeof(conn));
    conn.fd = -1;
    g_ssl_new_fail = 1;
    assert_int_equal(establish_tls_connection(&client, &conn, "h", 853, 10, 0, 0, NULL), -1);

    reset_stubs();
    memset(&conn, 0, sizeof(conn));
    conn.fd = -1;
    g_ssl_connect_rc = 0;
    assert_int_equal(establish_tls_connection(&client, &conn, "h", 853, 10, 0, 0, NULL), -1);

    reset_stubs();
    memset(&conn, 0, sizeof(conn));
    conn.fd = -1;
    assert_int_equal(establish_tls_connection(&client, &conn, "host.example", 853, 10, 0, 0, NULL), 0);
    assert_string_equal(conn.host, "host.example");
    assert_int_equal(conn.port, 853);
    close_connection(&conn);
    close_connection(NULL);
}

static void test_dot_resolve_success_and_failures(void **state) {
    (void)state;
    reset_stubs();

    upstream_config_t cfg = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };

    upstream_dot_client_t *client = NULL;
    assert_int_equal(upstream_dot_client_init(&client, &cfg), 0);
    assert_non_null(client);

    upstream_server_t server;
    memset(&server, 0, sizeof(server));
    server.type = UPSTREAM_TYPE_DOT;
    strcpy(server.host, "127.0.0.1");
    server.port = 853;

    uint8_t query[] = {0x12, 0x34};
    uint8_t *resp = NULL;
    size_t resp_len = 0;

    const uint8_t dns_resp[] = {0x12, 0x34, 0x81, 0x80};
    uint8_t framed[6] = {0x00, 0x04, dns_resp[0], dns_resp[1], dns_resp[2], dns_resp[3]};
    g_ssl_read_data = framed;
    g_ssl_read_data_len = sizeof(framed);
    g_ssl_read_script[0] = 2;
    g_ssl_read_script[1] = 4;
    g_ssl_read_script_len = 2;
    g_ssl_write_script[0] = 2;
    g_ssl_write_script[1] = 2;
    g_ssl_write_script_len = 2;

    g_dns_validate_rc = -1;
    assert_int_equal(upstream_dot_resolve(client, &server, 20, query, sizeof(query), &resp, &resp_len), -1);

    /* Existing live connection to different host/port forces reconnect branch */
    client->pool[0].fd = 7;
    client->pool[0].ssl = (SSL *)(uintptr_t)0x44;
    strcpy(client->pool[0].host, "old.example");
    client->pool[0].port = 853;
    reset_stubs();
    g_ssl_read_data = framed;
    g_ssl_read_data_len = sizeof(framed);
    g_ssl_read_script[0] = 2;
    g_ssl_read_script[1] = 4;
    g_ssl_read_script_len = 2;
    g_ssl_write_script[0] = -1; /* triggers write failure branch */
    g_ssl_write_script_len = 1;
    assert_int_equal(upstream_dot_resolve(client, &server, 20, query, sizeof(query), &resp, &resp_len), -1);

    reset_stubs();
    g_ssl_read_data = framed;
    g_ssl_read_data_len = sizeof(framed);
    g_ssl_read_script[0] = 2;
    g_ssl_read_script[1] = 4;
    g_ssl_read_script_len = 2;
    g_ssl_write_script[0] = 2;
    g_ssl_write_script[1] = 2;
    g_ssl_write_script_len = 2;
    g_malloc_fail_on_call = 1; /* response buffer alloc failure */
    assert_int_equal(upstream_dot_resolve(client, &server, 20, query, sizeof(query), &resp, &resp_len), -1);

    reset_stubs();
    g_ssl_read_data = framed;
    g_ssl_read_data_len = sizeof(framed);
    g_ssl_read_script[0] = 2;
    g_ssl_read_script[1] = 4;
    g_ssl_read_script_len = 2;
    g_ssl_write_script[0] = 2;
    g_ssl_write_script[1] = 2;
    g_ssl_write_script_len = 2;
    assert_int_equal(upstream_dot_resolve(client, &server, 20, query, sizeof(query), &resp, &resp_len), 0);
    assert_non_null(resp);
    assert_int_equal((int)resp_len, 4);
    free(resp);

    client->pool[0].in_use = 1;
    client->pool[0].fd = 5;
    client->pool[0].ssl = (SSL *)(uintptr_t)0x22;
    int cap = 0;
    int in_use = 0;
    int alive = 0;
    assert_int_equal(upstream_dot_client_get_pool_stats(client, &cap, &in_use, &alive), 0);
    assert_int_equal(cap, 1);
    assert_int_equal(in_use, 1);
    assert_int_equal(alive, 1);

    upstream_dot_client_destroy(client);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_connect_with_timeout_edge_paths),
        cmocka_unit_test(test_ssl_io_helpers),
        cmocka_unit_test(test_dot_client_init_failure_paths),
        cmocka_unit_test(test_establish_tls_connection_paths),
        cmocka_unit_test(test_dot_resolve_success_and_failures),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
