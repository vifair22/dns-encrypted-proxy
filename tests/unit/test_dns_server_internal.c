#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>

#include "config.h"
#include "cache.h"
#include "upstream.h"
#include "metrics.h"
#include "dns_message.h"
#include "dns_server.h"
#include "test_fixtures.h"

static int g_stub_key_ok = 0;
static size_t g_stub_key_len = 0;
static int g_stub_cache_lookup_hit = 0;
static const uint8_t *g_stub_cache_lookup_resp = NULL;
static size_t g_stub_cache_lookup_resp_len = 0;
static int g_stub_upstream_rc = -1;
static const uint8_t *g_stub_upstream_resp = NULL;
static size_t g_stub_upstream_resp_len = 0;
static int g_stub_cacheable = 0;
static int g_stub_ttl_ok = 0;
static uint32_t g_stub_min_ttl = 0;
static int g_stub_cache_store_calls = 0;
static int g_stub_hosts_lookup_hit = 0;
static uint32_t g_stub_hosts_lookup_addr_be = 0;
static uint8_t g_huge_response[70000];
static int g_stub_dns_cache_init_rc = 0;
static int g_stub_upstream_client_init_rc = 0;
static int g_stub_upstream_facilitator_init_rc = 0;
static int g_stub_dns_cache_destroy_calls = 0;
static int g_stub_upstream_client_destroy_calls = 0;
static int g_stub_upstream_facilitator_destroy_calls = 0;
static uint32_t dns_server_rng_state = 0x89ABCDEFu;
static int g_wrap_poll_script[16];
static int g_wrap_poll_script_len = 0;
static int g_wrap_poll_script_idx = 0;
static ssize_t g_wrap_recvfrom_return = -1;
static const uint8_t *g_wrap_recvfrom_data = NULL;
static size_t g_wrap_recvfrom_data_len = 0;
static ssize_t g_wrap_sendto_return = -1;
static int g_wrap_pthread_create_fail_on_call = 0;
static int g_wrap_pthread_create_calls = 0;
static int g_wrap_pthread_detach_calls = 0;
static int g_wrap_calloc_fail_tcp_ctx_once = 0;
static int g_wrap_socket_fail_udp_once = 0;
static int g_wrap_socket_fail_tcp_once = 0;
static int g_wrap_bind_fail_once = 0;
static int g_wrap_listen_fail_once = 0;
static int g_wrap_accept_script[8];
static int g_wrap_accept_script_len = 0;
static int g_wrap_accept_script_idx = 0;
static int g_wrap_recv_script[8];
static int g_wrap_recv_script_len = 0;
static int g_wrap_recv_script_idx = 0;
static int g_wrap_send_script[8];
static int g_wrap_send_script_len = 0;
static int g_wrap_send_script_idx = 0;
static int g_wrap_malloc_fail_on_call = 0;
static int g_wrap_malloc_calls = 0;

static int reserve_unused_port_local(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }

    int port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static uint32_t dns_server_next_rand(void) {
    dns_server_rng_state = dns_server_rng_state * 1103515245u + 12345u;
    return dns_server_rng_state;
}

static void reset_stubs(void) {
    g_stub_key_ok = 0;
    g_stub_key_len = 0;
    g_stub_cache_lookup_hit = 0;
    g_stub_cache_lookup_resp = NULL;
    g_stub_cache_lookup_resp_len = 0;
    g_stub_upstream_rc = -1;
    g_stub_upstream_resp = NULL;
    g_stub_upstream_resp_len = 0;
    g_stub_cacheable = 0;
    g_stub_ttl_ok = 0;
    g_stub_min_ttl = 0;
    g_stub_cache_store_calls = 0;
    g_stub_hosts_lookup_hit = 0;
    g_stub_hosts_lookup_addr_be = 0;
    g_stub_dns_cache_init_rc = 0;
    g_stub_upstream_client_init_rc = 0;
    g_stub_upstream_facilitator_init_rc = 0;
    g_stub_dns_cache_destroy_calls = 0;
    g_stub_upstream_client_destroy_calls = 0;
    g_stub_upstream_facilitator_destroy_calls = 0;
    g_wrap_poll_script_len = 0;
    g_wrap_poll_script_idx = 0;
    g_wrap_recvfrom_return = -1;
    g_wrap_recvfrom_data = NULL;
    g_wrap_recvfrom_data_len = 0;
    g_wrap_sendto_return = -1;
    g_wrap_pthread_create_fail_on_call = 0;
    g_wrap_pthread_create_calls = 0;
    g_wrap_pthread_detach_calls = 0;
    g_wrap_calloc_fail_tcp_ctx_once = 0;
    g_wrap_socket_fail_udp_once = 0;
    g_wrap_socket_fail_tcp_once = 0;
    g_wrap_bind_fail_once = 0;
    g_wrap_listen_fail_once = 0;
    g_wrap_accept_script_len = 0;
    g_wrap_accept_script_idx = 0;
    g_wrap_recv_script_len = 0;
    g_wrap_recv_script_idx = 0;
    g_wrap_send_script_len = 0;
    g_wrap_send_script_idx = 0;
    g_wrap_malloc_fail_on_call = 0;
    g_wrap_malloc_calls = 0;
}

static void *dns_server_wrap_malloc(size_t size) {
    g_wrap_malloc_calls++;
    if (g_wrap_malloc_fail_on_call > 0 && g_wrap_malloc_calls == g_wrap_malloc_fail_on_call) {
        return NULL;
    }
    return malloc(size);
}

static int dns_server_wrap_socket(int domain, int type, int protocol) {
    if (type == SOCK_DGRAM && g_wrap_socket_fail_udp_once) {
        g_wrap_socket_fail_udp_once = 0;
        errno = EMFILE;
        return -1;
    }
    if (type == SOCK_STREAM && g_wrap_socket_fail_tcp_once) {
        g_wrap_socket_fail_tcp_once = 0;
        errno = EMFILE;
        return -1;
    }
    return socket(domain, type, protocol);
}

static int dns_server_wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (g_wrap_bind_fail_once) {
        g_wrap_bind_fail_once = 0;
        errno = EADDRINUSE;
        return -1;
    }
    return bind(sockfd, addr, addrlen);
}

static int dns_server_wrap_listen(int sockfd, int backlog) {
    if (g_wrap_listen_fail_once) {
        g_wrap_listen_fail_once = 0;
        errno = EADDRINUSE;
        return -1;
    }
    return listen(sockfd, backlog);
}

static int dns_server_wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (g_wrap_accept_script_idx < g_wrap_accept_script_len) {
        int action = g_wrap_accept_script[g_wrap_accept_script_idx++];
        if (action == -100) {
            errno = EINTR;
            return -1;
        }
        if (action == -101) {
            errno = EIO;
            return -1;
        }
    }
    return accept(sockfd, addr, addrlen);
}

static ssize_t dns_server_wrap_recv(int sockfd, void *buf, size_t len, int flags) {
    if (g_wrap_recv_script_idx < g_wrap_recv_script_len) {
        int action = g_wrap_recv_script[g_wrap_recv_script_idx++];
        if (action == -100) {
            errno = EINTR;
            return -1;
        }
        if (action == -101) {
            errno = EIO;
            return -1;
        }
    }
    return recv(sockfd, buf, len, flags);
}

static ssize_t dns_server_wrap_send(int sockfd, const void *buf, size_t len, int flags) {
    (void)sockfd;
    (void)buf;
    if (g_wrap_send_script_idx < g_wrap_send_script_len) {
        int action = g_wrap_send_script[g_wrap_send_script_idx++];
        if (action == -100) {
            errno = EINTR;
            return -1;
        }
        if (action == -101) {
            errno = EIO;
            return -1;
        }
        if (action >= 0) {
            size_t n = (size_t)action;
            return (ssize_t)(n > len ? len : n);
        }
    }
    return send(sockfd, buf, len, flags);
}

static int dns_server_wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (g_wrap_poll_script_idx < g_wrap_poll_script_len) {
        int action = g_wrap_poll_script[g_wrap_poll_script_idx++];
        if (action == -100) {
            errno = EINTR;
            return -1;
        }
        if (action == -101) {
            errno = EIO;
            return -1;
        }
        if (action == 0) {
            return 0;
        }
        if (nfds > 0) {
            fds[0].revents = 0;
            if (action == 1) {
                fds[0].revents = POLLERR;
            } else if (action == 2) {
                fds[0].revents = 0;
            } else if (action == 3) {
                fds[0].revents = POLLIN;
            }
        }
        return 1;
    }
    return poll(fds, nfds, timeout);
}

static ssize_t dns_server_wrap_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    (void)fd;
    (void)flags;
    if (g_wrap_recvfrom_return >= 0 && g_wrap_recvfrom_data != NULL) {
        size_t n = (size_t)g_wrap_recvfrom_return;
        if (n > len) {
            n = len;
        }
        if (n > g_wrap_recvfrom_data_len) {
            n = g_wrap_recvfrom_data_len;
        }
        memcpy(buf, g_wrap_recvfrom_data, n);
        if (src_addr != NULL && addrlen != NULL && *addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in *a = (struct sockaddr_in *)src_addr;
            memset(a, 0, sizeof(*a));
            a->sin_family = AF_INET;
            a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a->sin_port = htons(5300);
            *addrlen = sizeof(*a);
        }
        g_wrap_recvfrom_return = -1;
        return (ssize_t)n;
    }
    return recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

static ssize_t dns_server_wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    (void)fd;
    (void)buf;
    (void)flags;
    (void)dest_addr;
    (void)addrlen;
    if (g_wrap_sendto_return >= 0) {
        ssize_t r = g_wrap_sendto_return;
        g_wrap_sendto_return = -1;
        return r;
    }
    return sendto(fd, buf, len, flags, dest_addr, addrlen);
}

static int dns_server_wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    g_wrap_pthread_create_calls++;
    if (g_wrap_pthread_create_fail_on_call > 0 && g_wrap_pthread_create_calls == g_wrap_pthread_create_fail_on_call) {
        return -1;
    }
    return pthread_create(thread, attr, start_routine, arg);
}

static int dns_server_wrap_pthread_detach(pthread_t thread) {
    (void)thread;
    g_wrap_pthread_detach_calls++;
    return 0;
}

static void *dns_server_wrap_calloc(size_t nmemb, size_t size) {
    if (g_wrap_calloc_fail_tcp_ctx_once) {
        g_wrap_calloc_fail_tcp_ctx_once = 0;
        return NULL;
    }
    return calloc(nmemb, size);
}

int dns_cache_init(dns_cache_t *cache, size_t capacity) {
    (void)cache;
    (void)capacity;
    return g_stub_dns_cache_init_rc;
}

void dns_cache_destroy(dns_cache_t *cache) {
    (void)cache;
    g_stub_dns_cache_destroy_calls++;
}

int dns_cache_lookup(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t request_id[2],
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)cache;
    (void)key;
    (void)key_len;
    if (!g_stub_cache_lookup_hit) {
        return 0;
    }
    if (response_out == NULL || response_len_out == NULL || g_stub_cache_lookup_resp == NULL || g_stub_cache_lookup_resp_len == 0) {
        return 0;
    }
    *response_out = malloc(g_stub_cache_lookup_resp_len);
    if (*response_out == NULL) {
        return 0;
    }
    memcpy(*response_out, g_stub_cache_lookup_resp, g_stub_cache_lookup_resp_len);
    (*response_out)[0] = request_id[0];
    (*response_out)[1] = request_id[1];
    *response_len_out = g_stub_cache_lookup_resp_len;
    return 1;
}

void dns_cache_store(
    dns_cache_t *cache,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *response,
    size_t response_len,
    uint32_t ttl_seconds) {
    (void)cache;
    (void)key;
    (void)key_len;
    (void)response;
    (void)response_len;
    (void)ttl_seconds;
    g_stub_cache_store_calls++;
}

int upstream_client_init(upstream_client_t *client, const char *urls[], int url_count, const upstream_config_t *config) {
    (void)client;
    (void)urls;
    (void)url_count;
    (void)config;
    return g_stub_upstream_client_init_rc;
}

void upstream_client_destroy(upstream_client_t *client) {
    (void)client;
    g_stub_upstream_client_destroy_calls++;
}

int upstream_client_set_bootstrap_ipv4(upstream_client_t *client, const char *host, uint32_t addr_v4_be) {
    (void)client;
    (void)host;
    (void)addr_v4_be;
    return 0;
}

int upstream_bootstrap_configure(upstream_client_t *client, const proxy_config_t *config) {
    (void)client;
    (void)config;
    return 0;
}

int upstream_facilitator_init(upstream_facilitator_t *facilitator, upstream_client_t *upstream) {
    (void)facilitator;
    (void)upstream;
    return g_stub_upstream_facilitator_init_rc;
}

void upstream_facilitator_destroy(upstream_facilitator_t *facilitator) {
    (void)facilitator;
    g_stub_upstream_facilitator_destroy_calls++;
}

int upstream_facilitator_resolve(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)facilitator;
    (void)query;
    (void)query_len;
    if (g_stub_upstream_rc != 0) {
        return -1;
    }
    if (response_out == NULL || response_len_out == NULL || g_stub_upstream_resp == NULL || g_stub_upstream_resp_len == 0) {
        return -1;
    }
    *response_out = malloc(g_stub_upstream_resp_len);
    if (*response_out == NULL) {
        return -1;
    }
    memcpy(*response_out, g_stub_upstream_resp, g_stub_upstream_resp_len);
    *response_len_out = g_stub_upstream_resp_len;
    return 0;
}

int upstream_facilitator_resolve_with_deadline(
    upstream_facilitator_t *facilitator,
    const uint8_t *query,
    size_t query_len,
    uint64_t deadline_ms,
    uint8_t **response_out,
    size_t *response_len_out) {
    (void)deadline_ms;
    return upstream_facilitator_resolve(facilitator, query, query_len, response_out, response_len_out);
}

void metrics_init(proxy_metrics_t *m) {
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

void logger_logf(const char *func, const char *level, const char *fmt, ...) {
    (void)func;
    (void)level;
    (void)fmt;
}

int config_lookup_hosts_a(const proxy_config_t *config, const char *name, uint32_t *addr_v4_be_out) {
    (void)config;
    (void)name;
    if (!g_stub_hosts_lookup_hit) {
        return 0;
    }
    if (addr_v4_be_out != NULL) {
        *addr_v4_be_out = g_stub_hosts_lookup_addr_be;
    }
    return 1;
}

int dns_extract_question_key(const uint8_t *query, size_t query_len, uint8_t *key_out, size_t key_capacity, size_t *key_len_out) {
    (void)query;
    (void)query_len;
    if (!g_stub_key_ok) {
        return -1;
    }
    if (key_out == NULL || key_len_out == NULL || key_capacity < g_stub_key_len || g_stub_key_len == 0) {
        return -1;
    }
    memset(key_out, 0xAB, g_stub_key_len);
    *key_len_out = g_stub_key_len;
    return 0;
}

int dns_question_section_length(const uint8_t *message, size_t message_len, size_t *section_len_out) {
    if (message == NULL || message_len < 12 || section_len_out == NULL) {
        return -1;
    }
    *section_len_out = message_len - 12;
    return 0;
}

size_t dns_udp_payload_limit_for_query(const uint8_t *query, size_t query_len) {
    (void)query;
    (void)query_len;
    return 512;
}

uint32_t dns_response_min_ttl(const uint8_t *message, size_t message_len, int *ok_out) {
    (void)message;
    (void)message_len;
    if (ok_out != NULL) {
        *ok_out = g_stub_ttl_ok;
    }
    return g_stub_min_ttl;
}

int dns_adjust_response_ttls(uint8_t *message, size_t message_len, uint32_t age_seconds) {
    (void)message;
    (void)message_len;
    (void)age_seconds;
    return 0;
}

int dns_response_is_cacheable(const uint8_t *response, size_t response_len) {
    (void)response;
    (void)response_len;
    return g_stub_cacheable;
}

int dns_validate_response_for_query(const uint8_t *query, size_t query_len, const uint8_t *response, size_t response_len) {
    (void)query;
    (void)query_len;
    (void)response;
    (void)response_len;
    return 0;
}

#define poll dns_server_wrap_poll
#define recvfrom dns_server_wrap_recvfrom
#define sendto dns_server_wrap_sendto
#define socket dns_server_wrap_socket
#define bind dns_server_wrap_bind
#define listen dns_server_wrap_listen
#define accept dns_server_wrap_accept
#define recv dns_server_wrap_recv
#define send dns_server_wrap_send
#define malloc dns_server_wrap_malloc
#define pthread_create dns_server_wrap_pthread_create
#define pthread_detach dns_server_wrap_pthread_detach
#define calloc dns_server_wrap_calloc
#include "../../src/dns_server.c"
#undef calloc
#undef malloc
#undef pthread_detach
#undef pthread_create
#undef send
#undef recv
#undef accept
#undef listen
#undef bind
#undef socket
#undef sendto
#undef recvfrom
#undef poll

static void test_dns_wire_helpers_branches(void **state) {
    (void)state;
    reset_stubs();

    size_t off = 0;
    const uint8_t name_ok[] = {0x03, 'w', 'w', 'w', 0x00};
    assert_int_equal(dns_skip_name_wire(name_ok, sizeof(name_ok), &off), 0);
    assert_int_equal(off, 5);

    off = 0;
    const uint8_t name_ptr[] = {0xC0, 0x0C};
    assert_int_equal(dns_skip_name_wire(name_ptr, sizeof(name_ptr), &off), 0);
    assert_int_equal(off, 2);

    off = 0;
    const uint8_t name_bad_ptr[] = {0xC0};
    assert_int_equal(dns_skip_name_wire(name_bad_ptr, sizeof(name_bad_ptr), &off), -1);

    off = 0;
    const uint8_t name_bad_label[] = {0x80, 0x00};
    assert_int_equal(dns_skip_name_wire(name_bad_label, sizeof(name_bad_label), &off), -1);
}

static void test_servfail_and_truncated_builders(void **state) {
    (void)state;
    reset_stubs();

    uint8_t *servfail = NULL;
    size_t servfail_len = 0;
    assert_int_equal(
        build_servfail_response(
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &servfail,
            &servfail_len),
        0);
    assert_true(servfail_len >= 12);
    uint16_t flags = (uint16_t)(((uint16_t)servfail[2] << 8) | servfail[3]);
    assert_int_equal((flags & 0x000Fu), 2);
    free(servfail);

    uint8_t *tr = NULL;
    size_t tr_len = 0;
    assert_int_equal(build_truncated_udp_response(DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN, 1500, &tr, &tr_len), -1);

    const size_t answer_count = 32;
    const size_t question_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN - 12;
    const size_t answer_len = 16;
    size_t big_len = 12 + question_len + answer_count * answer_len;
    uint8_t *big = calloc(1, big_len);
    assert_non_null(big);
    big[0] = 0x12;
    big[1] = 0x34;
    big[2] = 0x81;
    big[3] = 0x80;
    big[4] = 0x00;
    big[5] = 0x01;
    big[6] = 0x00;
    big[7] = (uint8_t)answer_count;
    memcpy(big + 12, DNS_QUERY_WWW_EXAMPLE_COM_A + 12, question_len);
    size_t w = 12 + question_len;
    for (size_t i = 0; i < answer_count; i++) {
        big[w + 0] = 0xC0; big[w + 1] = 0x0C;
        big[w + 2] = 0x00; big[w + 3] = 0x01;
        big[w + 4] = 0x00; big[w + 5] = 0x01;
        big[w + 10] = 0x00; big[w + 11] = 0x04;
        big[w + 12] = 1; big[w + 13] = 2; big[w + 14] = 3; big[w + 15] = (uint8_t)i;
        w += answer_len;
    }
    assert_int_equal(build_truncated_udp_response(big, big_len, 512, &tr, &tr_len), 0);
    assert_true(tr_len <= 512);
    flags = (uint16_t)(((uint16_t)tr[2] << 8) | tr[3]);
    assert_true((flags & 0x0200u) != 0);
    free(tr);
    free(big);

    /* Malformed response should produce minimal truncated SERVFAIL-style frame */
    uint8_t malformed[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01};
    tr = NULL;
    tr_len = 0;
    assert_int_equal(build_truncated_udp_response(malformed, sizeof(malformed), 512, &tr, &tr_len), -1);
}

static void test_io_and_socket_helpers(void **state) {
    (void)state;
    reset_stubs();

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    uint8_t buf[2] = {0};
    uint8_t one = 0xAA;
    assert_int_equal((int)write(sv[1], &one, 1), 1);
    close(sv[1]);

    assert_int_equal(recv_all_with_timeout(sv[0], buf, 2, 0), 0);
    close(sv[0]);

    int fd = -1;
    const uint8_t data[1] = {0};
    assert_int_equal(send_all(fd, data, sizeof(data)), -1);

    proxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.listen_addr, "bad.addr");
    cfg.listen_port = 5300;
    assert_int_equal(create_udp_socket(&cfg), -1);
    assert_int_equal(create_tcp_socket(&cfg), -1);

    /* recv timeout path */
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    assert_int_equal(recv_all_with_timeout(sv[0], buf, 1, 10), -2);
    close(sv[0]);
    close(sv[1]);

    /* send success path */
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    const uint8_t out_data[3] = {1, 2, 3};
    assert_int_equal(send_all(sv[0], out_data, sizeof(out_data)), 0);
    uint8_t in_data[3] = {0};
    assert_int_equal((int)recv(sv[1], in_data, sizeof(in_data), 0), 3);
    assert_memory_equal(in_data, out_data, sizeof(out_data));
    close(sv[0]);
    close(sv[1]);
}

static void test_process_query_branches(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));

    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(process_query(NULL, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &out, &out_len), -1);

    g_stub_hosts_lookup_hit = 1;
    g_stub_hosts_lookup_addr_be = htonl(0x01020304u);
    assert_int_equal(process_query(&server, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &out, &out_len), 0);
    assert_non_null(out);
    assert_true(out_len >= 16);
    assert_int_equal(out[out_len - 4], 1);
    assert_int_equal(out[out_len - 3], 2);
    assert_int_equal(out[out_len - 2], 3);
    assert_int_equal(out[out_len - 1], 4);
    free(out);
    out = NULL;
    g_stub_hosts_lookup_hit = 0;

    g_stub_key_ok = 1;
    g_stub_key_len = 8;
    g_stub_cache_lookup_hit = 1;
    g_stub_cache_lookup_resp = DNS_RESPONSE_WWW_EXAMPLE_COM_A;
    g_stub_cache_lookup_resp_len = DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN;
    assert_int_equal(process_query(&server, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &out, &out_len), 0);
    assert_non_null(out);
    free(out);
    out = NULL;
    assert_int_equal((uint64_t)atomic_load(&server.metrics.cache_hits), 1);

    reset_stubs();
    g_stub_key_ok = 1;
    g_stub_key_len = 8;
    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = DNS_RESPONSE_WWW_EXAMPLE_COM_A;
    g_stub_upstream_resp_len = DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN;
    g_stub_cacheable = 1;
    g_stub_ttl_ok = 1;
    g_stub_min_ttl = 60;
    assert_int_equal(process_query(&server, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &out, &out_len), 0);
    assert_non_null(out);
    free(out);
    out = NULL;
    assert_true(g_stub_cache_store_calls >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.upstream_success) >= 1);

    reset_stubs();
    g_stub_key_ok = 1;
    g_stub_key_len = 8;
    assert_int_equal(process_query(&server, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &out, &out_len), 0);
    assert_non_null(out);
    free(out);
    assert_true((uint64_t)atomic_load(&server.metrics.upstream_failures) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.servfail_sent) >= 1);
}

static void test_proxy_server_init_and_socket_success_paths(void **state) {
    (void)state;
    reset_stubs();

    assert_int_equal(proxy_server_init(NULL, NULL, NULL), -1);

    proxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.listen_addr, "127.0.0.1");
    cfg.listen_port = reserve_unused_port_local();
    cfg.cache_capacity = 16;
    cfg.upstream_count = 1;
    strcpy(cfg.upstream_urls[0], "https://example.invalid/dns-query");

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;

    g_stub_dns_cache_init_rc = -1;
    assert_int_equal(proxy_server_init(&server, &cfg, &stop), -1);

    reset_stubs();
    g_stub_upstream_client_init_rc = -1;
    assert_int_equal(proxy_server_init(&server, &cfg, &stop), -1);
    assert_true(g_stub_dns_cache_destroy_calls >= 1);

    reset_stubs();
    g_stub_upstream_facilitator_init_rc = -1;
    assert_int_equal(proxy_server_init(&server, &cfg, &stop), -1);
    assert_true(g_stub_upstream_client_destroy_calls >= 1);
    assert_true(g_stub_dns_cache_destroy_calls >= 1);

    reset_stubs();
    assert_int_equal(proxy_server_init(&server, &cfg, &stop), 0);
    proxy_server_destroy(&server);
    assert_true(g_stub_upstream_client_destroy_calls >= 1);
    assert_true(g_stub_upstream_facilitator_destroy_calls >= 1);
    assert_true(g_stub_dns_cache_destroy_calls >= 1);

    int udp_fd = create_udp_socket(&cfg);
    assert_true(udp_fd >= 0);
    int tcp_fd = create_tcp_socket(&cfg);
    assert_true(tcp_fd >= 0);
    close(udp_fd);
    close(tcp_fd);
}

static void test_dns_server_randomized_helper_exploration(void **state) {
    (void)state;
    reset_stubs();

    uint8_t msg[1024];
    for (int i = 0; i < 4000; i++) {
        size_t len = (size_t)(dns_server_next_rand() % sizeof(msg));
        for (size_t j = 0; j < len; j++) {
            msg[j] = (uint8_t)(dns_server_next_rand() & 0xFFu);
        }

        size_t off = 0;
        (void)dns_skip_name_wire(msg, len, &off);

        size_t rr_end = 0;
        (void)dns_rr_end_offset(msg, len, 0, &rr_end);

        size_t opt_s = 0, opt_e = 0;
        (void)dns_find_query_opt(msg, len, &opt_s, &opt_e);
        (void)dns_find_opt_record(msg, len, &opt_s, &opt_e);

        uint8_t *out = NULL;
        size_t out_len = 0;
        (void)build_servfail_response(msg, len, &out, &out_len);
        free(out);

        out = NULL;
        out_len = 0;
        size_t udp_limit = (size_t)(dns_server_next_rand() % 1200);
        (void)build_truncated_udp_response(msg, len, udp_limit, &out, &out_len);
        free(out);
    }
}

static void test_dns_server_specific_helper_paths(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    metrics_init(&server.metrics);

    metrics_record_response(NULL, NULL, 0);
    metrics_record_response(&server, NULL, 0);
    metrics_record_response(&server, DNS_RESPONSE_SERVFAIL, DNS_RESPONSE_SERVFAIL_LEN);
    assert_true((uint64_t)atomic_load(&server.metrics.responses_total) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.responses_rcode[2]) >= 1);

    size_t opt_s = 0, opt_e = 0;
    assert_int_equal(dns_find_query_opt(DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN, &opt_s, &opt_e), 0);
    assert_true(opt_e > opt_s);
    assert_int_equal(dns_find_query_opt(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &opt_s, &opt_e), -1);

    /* recv_all timeout branch via poll timeout and error via invalid fd */
    uint8_t buf[4] = {0};
    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    int r = recv_all_with_timeout(sv[0], buf, 1, 10);
    assert_true(r == -1 || r == -2);
    close(sv[0]);
    close(sv[1]);
    r = recv_all_with_timeout(-1, buf, 1, 10);
    assert_true(r == -1 || r == -2);

    /* send_all invalid fd branch */
    const uint8_t d[1] = {0};
    assert_int_equal(send_all(-1, d, 1), -1);
}

static void test_udp_loop_and_proxy_run_thread_failure_paths(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    strcpy(server.config.listen_addr, "127.0.0.1");
    server.config.listen_port = reserve_unused_port_local();
    server.config.cache_capacity = 16;
    server.config.upstream_count = 1;
    strcpy(server.config.upstream_urls[0], "https://example.invalid/dns-query");
    metrics_init(&server.metrics);

    socket_loop_ctx_t ctx = {.server = &server, .fd = 42};
    g_wrap_poll_script[0] = 3; /* POLLIN */
    g_wrap_poll_script[1] = 3; /* POLLIN */
    g_wrap_poll_script[2] = 1; /* POLLERR -> break */
    g_wrap_poll_script_len = 3;
    g_wrap_recvfrom_return = (ssize_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_recvfrom_data = DNS_QUERY_WWW_EXAMPLE_COM_A;
    g_wrap_recvfrom_data_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_sendto_return = (ssize_t)DNS_RESPONSE_SERVFAIL_LEN;
    g_stub_upstream_rc = -1;

    assert_ptr_equal(udp_loop(&ctx), NULL);

    /* proxy_server_run: fail first pthread_create */
    g_wrap_pthread_create_fail_on_call = 1;
    assert_int_equal(proxy_server_run(&server), -1);

    /* proxy_server_run: fail second pthread_create after udp thread starts */
    reset_stubs();
    strcpy(server.config.listen_addr, "127.0.0.1");
    server.config.listen_port = reserve_unused_port_local();
    server.stop_flag = &stop;
    g_wrap_pthread_create_fail_on_call = 2;
    g_wrap_poll_script[0] = 1; /* udp thread exits quickly */
    g_wrap_poll_script_len = 1;
    assert_int_equal(proxy_server_run(&server), -1);
}

static void test_tcp_client_loop_large_response_and_zero_length_query(void **state) {
    (void)state;
    reset_stubs();

    memset(g_huge_response, 0xCD, sizeof(g_huge_response));
    g_huge_response[0] = 0x12;
    g_huge_response[1] = 0x34;

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 100;
    server.config.tcp_max_queries_per_conn = 2;
    atomic_store(&server.active_tcp_clients, 1);
    metrics_init(&server.metrics);
    atomic_store(&server.metrics.tcp_connections_active, 1);

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    /* first frame: zero length (should be ignored) */
    uint8_t zero_prefix[2] = {0, 0};
    assert_int_equal((int)write(sv[1], zero_prefix, 2), 2);

    /* second frame: valid query with huge upstream response (len > UINT16_MAX) */
    uint16_t qlen = (uint16_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    uint8_t qprefix[2] = {(uint8_t)((qlen >> 8) & 0xFFu), (uint8_t)(qlen & 0xFFu)};
    assert_int_equal((int)write(sv[1], qprefix, 2), 2);
    assert_int_equal((int)write(sv[1], DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN), (int)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    close(sv[1]);

    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = g_huge_response;
    g_stub_upstream_resp_len = sizeof(g_huge_response);

    tcp_client_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    ctx->query_count = 0;

    assert_ptr_equal(tcp_client_loop(ctx), NULL);

    assert_int_equal((int)atomic_load(&server.active_tcp_clients), 0);
    assert_int_equal((int)atomic_load(&server.metrics.tcp_connections_active), 0);
}

static void test_dns_server_additional_edge_paths(void **state) {
    (void)state;
    reset_stubs();

    size_t rr_end = 0;
    assert_int_equal(dns_rr_end_offset(NULL, 0, 0, &rr_end), -1);
    assert_int_equal(dns_rr_end_offset(DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN, &rr_end), -1);

    size_t opt_s = 0;
    size_t opt_e = 0;
    assert_int_equal(dns_find_query_opt(DNS_MALFORMED_SHORT_HEADER, DNS_MALFORMED_SHORT_HEADER_LEN, &opt_s, &opt_e), -1);

    uint8_t bad_opt[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN];
    memcpy(bad_opt, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, sizeof(bad_opt));
    bad_opt[DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN - 1] = 0x20;
    assert_int_equal(dns_find_query_opt(bad_opt, sizeof(bad_opt), &opt_s, &opt_e), -1);

    uint8_t *resp = NULL;
    size_t resp_len = 0;
    assert_int_equal(build_servfail_response(DNS_MALFORMED_SHORT_HEADER, DNS_MALFORMED_SHORT_HEADER_LEN, &resp, &resp_len), -1);
    assert_int_equal(build_servfail_response(DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, NULL, &resp_len), -1);

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    metrics_init(&server.metrics);

    uint8_t tiny_resp[] = {0x12};
    g_stub_key_ok = 1;
    g_stub_key_len = 4;
    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = tiny_resp;
    g_stub_upstream_resp_len = sizeof(tiny_resp);
    assert_int_equal(process_query(&server, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, &resp, &resp_len), 0);
    assert_non_null(resp);
    assert_int_equal(resp_len, sizeof(tiny_resp));
    free(resp);

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    uint8_t byte = 0x5A;
    assert_int_equal((int)write(sv[1], &byte, 1), 1);
    g_wrap_poll_script[0] = -100;
    g_wrap_poll_script[1] = 3;
    g_wrap_poll_script_len = 2;
    g_wrap_poll_script_idx = 0;
    uint8_t got = 0;
    assert_int_equal(recv_all_with_timeout(sv[0], &got, 1, 25), 1);
    assert_int_equal(got, byte);
    close(sv[0]);
    close(sv[1]);

    volatile sig_atomic_t stop = 0;
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 50;
    server.config.tcp_max_queries_per_conn = 1;
    atomic_store(&server.active_tcp_clients, 1);
    metrics_init(&server.metrics);
    atomic_store(&server.metrics.tcp_connections_active, 1);

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    tcp_client_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    ctx->query_count = 1;
    assert_ptr_equal(tcp_client_loop(ctx), NULL);
    close(sv[1]);
    assert_int_equal((int)atomic_load(&server.active_tcp_clients), 0);
}

static void test_tcp_accept_loop_additional_paths(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    server.config.tcp_max_clients = 2;

    socket_loop_ctx_t ctx = {.server = &server, .fd = 42};
    g_wrap_poll_script[0] = -100; /* EINTR */
    g_wrap_poll_script[1] = -101; /* error -> break */
    g_wrap_poll_script_len = 2;
    assert_ptr_equal(tcp_accept_loop(&ctx), NULL);

    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_max_clients = 1;
    atomic_store(&server.active_tcp_clients, 1);
    ctx.server = &server;
    ctx.fd = 42;
    g_wrap_poll_script[0] = 3; /* POLLIN */
    g_wrap_poll_script[1] = 1; /* POLLERR */
    g_wrap_poll_script_len = 2;
    assert_ptr_equal(tcp_accept_loop(&ctx), NULL);
    assert_true((uint64_t)atomic_load(&server.metrics.tcp_connections_rejected) >= 1);

    proxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.listen_addr, "127.0.0.1");
    cfg.listen_port = reserve_unused_port_local();
    int listen_fd = create_tcp_socket(&cfg);
    assert_true(listen_fd >= 0);

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(client_fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)cfg.listen_port);
    assert_int_equal(connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_max_clients = 4;
    ctx.server = &server;
    ctx.fd = listen_fd;
    g_wrap_poll_script[0] = 3; /* POLLIN */
    g_wrap_poll_script[1] = 1; /* stop loop */
    g_wrap_poll_script_len = 2;
    g_wrap_pthread_create_fail_on_call = 1;
    assert_ptr_equal(tcp_accept_loop(&ctx), NULL);
    close(client_fd);

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(client_fd >= 0);
    assert_int_equal(connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_max_clients = 4;
    ctx.server = &server;
    ctx.fd = listen_fd;
    g_wrap_poll_script[0] = 3; /* POLLIN */
    g_wrap_poll_script[1] = 1; /* stop loop */
    g_wrap_poll_script_len = 2;
    g_wrap_calloc_fail_tcp_ctx_once = 1;
    assert_ptr_equal(tcp_accept_loop(&ctx), NULL);

    close(client_fd);
    close(listen_fd);
}

static void test_dns_server_socket_and_accept_error_paths(void **state) {
    (void)state;
    reset_stubs();

    proxy_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.listen_addr, "127.0.0.1");
    cfg.listen_port = reserve_unused_port_local();

    g_wrap_socket_fail_udp_once = 1;
    assert_int_equal(create_udp_socket(&cfg), -1);

    g_wrap_socket_fail_tcp_once = 1;
    assert_int_equal(create_tcp_socket(&cfg), -1);

    g_wrap_bind_fail_once = 1;
    assert_int_equal(create_udp_socket(&cfg), -1);

    g_wrap_bind_fail_once = 1;
    assert_int_equal(create_tcp_socket(&cfg), -1);

    g_wrap_listen_fail_once = 1;
    assert_int_equal(create_tcp_socket(&cfg), -1);

    int listen_fd = create_tcp_socket(&cfg);
    assert_true(listen_fd >= 0);

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    server.config.tcp_max_clients = 10;
    socket_loop_ctx_t ctx = {.server = &server, .fd = listen_fd};

    g_wrap_poll_script[0] = 2; /* ready but no POLLIN -> continue */
    g_wrap_poll_script[1] = 3; /* POLLIN */
    g_wrap_poll_script[2] = 3; /* POLLIN */
    g_wrap_poll_script[3] = 1; /* POLLERR -> break */
    g_wrap_poll_script_len = 4;
    g_wrap_accept_script[0] = -100; /* EINTR */
    g_wrap_accept_script[1] = -101; /* hard error */
    g_wrap_accept_script_len = 2;
    assert_ptr_equal(tcp_accept_loop(&ctx), NULL);

    reset_stubs();
    memset(&server, 0, sizeof(server));
    strcpy(server.config.listen_addr, "127.0.0.1");
    server.config.listen_port = reserve_unused_port_local();
    g_wrap_listen_fail_once = 1;
    assert_int_equal(proxy_server_run(&server), -1);

    close(listen_fd);
}

static void test_dns_server_recv_send_eintr_paths(void **state) {
    (void)state;
    reset_stubs();

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    uint8_t b = 0x2A;
    assert_int_equal((int)write(sv[1], &b, 1), 1);

    g_wrap_poll_script[0] = 3;
    g_wrap_poll_script[1] = 3;
    g_wrap_poll_script_len = 2;
    g_wrap_recv_script[0] = -100;
    g_wrap_recv_script_len = 1;

    uint8_t out = 0;
    assert_int_equal(recv_all_with_timeout(sv[0], &out, 1, 50), 1);
    assert_int_equal(out, b);
    close(sv[0]);
    close(sv[1]);

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    g_wrap_poll_script_idx = 0;
    g_wrap_poll_script[0] = 3;
    g_wrap_poll_script_len = 1;
    g_wrap_recv_script_idx = 0;
    g_wrap_recv_script[0] = -101;
    g_wrap_recv_script_len = 1;
    assert_int_equal(recv_all_with_timeout(sv[0], &out, 1, 50), -1);
    close(sv[0]);
    close(sv[1]);

    uint8_t payload[3] = {1, 2, 3};
    g_wrap_send_script[0] = -100;
    g_wrap_send_script[1] = 1;
    g_wrap_send_script[2] = 2;
    g_wrap_send_script_len = 3;
    assert_int_equal(send_all(-1, payload, sizeof(payload)), 0);

    proxy_server_destroy(NULL);
}

static void test_dns_server_tcp_client_error_branches(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 50;
    server.config.tcp_max_queries_per_conn = 0;
    atomic_store(&server.active_tcp_clients, 1);
    metrics_init(&server.metrics);
    atomic_store(&server.metrics.tcp_connections_active, 1);

    int sv[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    uint16_t qlen = 32;
    uint8_t prefix[2] = {(uint8_t)(qlen >> 8), (uint8_t)(qlen & 0xFFu)};
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    g_wrap_malloc_fail_on_call = 2;
    tcp_client_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);
    close(sv[1]);

    atomic_store(&server.active_tcp_clients, 1);
    atomic_store(&server.metrics.tcp_connections_active, 1);
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    qlen = 1;
    prefix[0] = 0;
    prefix[1] = 1;
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    uint8_t badq = 0xFF;
    assert_int_equal((int)write(sv[1], &badq, 1), 1);
    close(sv[1]);
    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);

    atomic_store(&server.active_tcp_clients, 1);
    atomic_store(&server.metrics.tcp_connections_active, 1);
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    qlen = (uint16_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    prefix[0] = (uint8_t)(qlen >> 8);
    prefix[1] = (uint8_t)(qlen & 0xFFu);
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    assert_int_equal((int)write(sv[1], DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN), (int)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    close(sv[1]);
    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = DNS_RESPONSE_WWW_EXAMPLE_COM_A;
    g_stub_upstream_resp_len = DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_send_script[0] = -101;
    g_wrap_send_script_len = 1;
    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);
}

static void test_dns_server_udp_loop_truncation_fallback(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    metrics_init(&server.metrics);

    uint8_t malformed_large[600];
    memset(malformed_large, 0xAA, sizeof(malformed_large));
    malformed_large[0] = 0x12;
    malformed_large[1] = 0x34;
    malformed_large[2] = 0x81;
    malformed_large[3] = 0x80;
    malformed_large[4] = 0xFF;
    malformed_large[5] = 0xFF;

    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = malformed_large;
    g_stub_upstream_resp_len = sizeof(malformed_large);
    g_stub_key_ok = 1;
    g_stub_key_len = 8;

    socket_loop_ctx_t ctx = {.server = &server, .fd = 42};
    g_wrap_poll_script[0] = 3;
    g_wrap_poll_script[1] = 1;
    g_wrap_poll_script_len = 2;
    g_wrap_recvfrom_return = (ssize_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_recvfrom_data = DNS_QUERY_WWW_EXAMPLE_COM_A;
    g_wrap_recvfrom_data_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_sendto_return = (ssize_t)DNS_RESPONSE_SERVFAIL_LEN;

    assert_ptr_equal(udp_loop(&ctx), NULL);
    assert_true((uint64_t)atomic_load(&server.metrics.truncated_sent) >= 1);

    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    metrics_init(&server.metrics);

    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = malformed_large;
    g_stub_upstream_resp_len = sizeof(malformed_large);
    g_stub_key_ok = 1;
    g_stub_key_len = 8;

    ctx.server = &server;
    ctx.fd = 42;
    g_wrap_poll_script[0] = 3;
    g_wrap_poll_script[1] = 1;
    g_wrap_poll_script_len = 2;
    g_wrap_recvfrom_return = (ssize_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_recvfrom_data = DNS_QUERY_WWW_EXAMPLE_COM_A;
    g_wrap_recvfrom_data_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_sendto_return = (ssize_t)DNS_RESPONSE_SERVFAIL_LEN;
    g_wrap_malloc_fail_on_call = 2;

    assert_ptr_equal(udp_loop(&ctx), NULL);
    assert_true((uint64_t)atomic_load(&server.metrics.servfail_sent) >= 1);

}

static void test_dns_server_udp_truncation_and_servfail_build_fail(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    metrics_init(&server.metrics);

    uint8_t malformed_large[600];
    memset(malformed_large, 0xAA, sizeof(malformed_large));
    malformed_large[0] = 0x12;
    malformed_large[1] = 0x34;
    malformed_large[2] = 0x81;
    malformed_large[3] = 0x80;
    malformed_large[4] = 0xFF;
    malformed_large[5] = 0xFF;

    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = malformed_large;
    g_stub_upstream_resp_len = sizeof(malformed_large);
    g_stub_key_ok = 1;
    g_stub_key_len = 8;

    socket_loop_ctx_t ctx = {.server = &server, .fd = 42};
    g_wrap_poll_script[0] = 3;
    g_wrap_poll_script[1] = 1;
    g_wrap_poll_script_len = 2;
    g_wrap_recvfrom_return = (ssize_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_recvfrom_data = DNS_QUERY_WWW_EXAMPLE_COM_A;
    g_wrap_recvfrom_data_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_sendto_return = (ssize_t)DNS_RESPONSE_SERVFAIL_LEN;

    g_wrap_malloc_fail_on_call = 2; /* fail truncation buffer alloc (1st malloc is udp buffer) */
    g_wrap_calloc_fail_tcp_ctx_once = 1; /* fail build_servfail_response alloc */

    assert_ptr_equal(udp_loop(&ctx), NULL);
    assert_int_equal((uint64_t)atomic_load(&server.metrics.queries_udp), 1);
    assert_int_equal((uint64_t)atomic_load(&server.metrics.truncated_sent), 0);
    assert_int_equal((uint64_t)atomic_load(&server.metrics.servfail_sent), 0);
}

static void test_dns_server_name_skip_steps_limit(void **state) {
    (void)state;
    reset_stubs();

    uint8_t msg[700];
    size_t p = 0;
    for (int i = 0; i < 260 && p + 2 < sizeof(msg); i++) {
        msg[p++] = 1;
        msg[p++] = 'a';
    }
    msg[p++] = 0;
    size_t off = 0;
    assert_int_equal(dns_skip_name_wire(msg, p, &off), -1);
}

static void test_dns_server_tcp_loop_specific_fail_paths(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 50;
    server.config.tcp_max_queries_per_conn = 0;
    metrics_init(&server.metrics);

    int sv[2];
    uint8_t prefix[2];
    tcp_client_ctx_t *ctx;

    /* recv body failure -> lines free(query)/break */
    atomic_store(&server.active_tcp_clients, 1);
    atomic_store(&server.metrics.tcp_connections_active, 1);
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    uint16_t qlen = 8;
    prefix[0] = (uint8_t)(qlen >> 8);
    prefix[1] = (uint8_t)(qlen & 0xFFu);
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    close(sv[1]);
    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);

    /* process_query failure with too-short DNS message */
    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 50;
    metrics_init(&server.metrics);
    atomic_store(&server.active_tcp_clients, 1);
    atomic_store(&server.metrics.tcp_connections_active, 1);
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    prefix[0] = 0;
    prefix[1] = 1;
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    uint8_t tiny = 0x01;
    assert_int_equal((int)write(sv[1], &tiny, 1), 1);
    close(sv[1]);
    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);

    /* response length > UINT16_MAX path */
    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 50;
    metrics_init(&server.metrics);
    atomic_store(&server.active_tcp_clients, 1);
    atomic_store(&server.metrics.tcp_connections_active, 1);
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    qlen = (uint16_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    prefix[0] = (uint8_t)(qlen >> 8);
    prefix[1] = (uint8_t)(qlen & 0xFFu);
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    assert_int_equal((int)write(sv[1], DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN), (int)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    close(sv[1]);
    memset(g_huge_response, 0xAB, sizeof(g_huge_response));
    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = g_huge_response;
    g_stub_upstream_resp_len = sizeof(g_huge_response);
    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);

    /* send failure branch after successful response build */
    reset_stubs();
    memset(&server, 0, sizeof(server));
    server.stop_flag = &stop;
    server.config.tcp_idle_timeout_ms = 50;
    metrics_init(&server.metrics);
    atomic_store(&server.active_tcp_clients, 1);
    atomic_store(&server.metrics.tcp_connections_active, 1);
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    qlen = (uint16_t)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    prefix[0] = (uint8_t)(qlen >> 8);
    prefix[1] = (uint8_t)(qlen & 0xFFu);
    assert_int_equal((int)write(sv[1], prefix, 2), 2);
    assert_int_equal((int)write(sv[1], DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN), (int)DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    close(sv[1]);
    g_stub_upstream_rc = 0;
    g_stub_upstream_resp = DNS_RESPONSE_WWW_EXAMPLE_COM_A;
    g_stub_upstream_resp_len = DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN;
    g_wrap_send_script_idx = 0;
    g_wrap_send_script[0] = -101;
    g_wrap_send_script_len = 1;
    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->server = &server;
    ctx->client_fd = sv[0];
    assert_ptr_equal(tcp_client_loop(ctx), NULL);
}

static void test_dns_server_udp_loop_poll_and_process_fail_paths(void **state) {
    (void)state;
    reset_stubs();

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    volatile sig_atomic_t stop = 0;
    server.stop_flag = &stop;
    metrics_init(&server.metrics);

    static const uint8_t short_query[5] = {0x12, 0x34, 0x01, 0x00, 0x00};

    socket_loop_ctx_t ctx = {.server = &server, .fd = 42};
    g_wrap_poll_script[0] = -100; /* EINTR branch */
    g_wrap_poll_script[1] = 2;    /* no POLLIN -> continue branch */
    g_wrap_poll_script[2] = 3;    /* POLLIN */
    g_wrap_poll_script[3] = 1;    /* POLLERR -> break */
    g_wrap_poll_script_len = 4;

    g_wrap_recvfrom_return = (ssize_t)sizeof(short_query);
    g_wrap_recvfrom_data = short_query;
    g_wrap_recvfrom_data_len = sizeof(short_query);

    assert_ptr_equal(udp_loop(&ctx), NULL);
    assert_int_equal((uint64_t)atomic_load(&server.metrics.queries_udp), 0);
}

static void test_hosts_override_edns_and_parser_edges(void **state) {
    (void)state;
    reset_stubs();

    char name[256];
    size_t q_end = 0;
    assert_int_equal(
        dns_extract_single_question_name_a(
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
            name,
            sizeof(name),
            &q_end),
        0);
    assert_string_equal(name, "www.example.com");

    uint8_t bad_qd[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_qd, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_qd));
    bad_qd[4] = 0x00;
    bad_qd[5] = 0x02;
    assert_int_equal(dns_extract_single_question_name_a(bad_qd, sizeof(bad_qd), name, sizeof(name), &q_end), -1);

    uint8_t bad_qtype[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_qtype, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_qtype));
    bad_qtype[sizeof(bad_qtype) - 4] = 0x00;
    bad_qtype[sizeof(bad_qtype) - 3] = 0x1C;
    assert_int_equal(dns_extract_single_question_name_a(bad_qtype, sizeof(bad_qtype), name, sizeof(name), &q_end), -1);

    uint8_t bad_label[DNS_QUERY_WWW_EXAMPLE_COM_A_LEN];
    memcpy(bad_label, DNS_QUERY_WWW_EXAMPLE_COM_A, sizeof(bad_label));
    bad_label[12] = 0xC0;
    assert_int_equal(dns_extract_single_question_name_a(bad_label, sizeof(bad_label), name, sizeof(name), &q_end), -1);

    assert_int_equal(build_hosts_a_response(NULL, 0, htonl(0x01020304u), NULL, NULL), -1);

    uint8_t *direct = NULL;
    size_t direct_len = 0;
    assert_int_equal(
        build_hosts_a_response(
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
            htonl(0x05060708u),
            &direct,
            &direct_len),
        0);
    assert_non_null(direct);
    assert_true(direct_len > 20);
    free(direct);

    proxy_server_t server;
    memset(&server, 0, sizeof(server));
    metrics_init(&server.metrics);

    g_stub_hosts_lookup_hit = 1;
    g_stub_hosts_lookup_addr_be = htonl(0x01020304u);

    uint8_t *out = NULL;
    size_t out_len = 0;
    assert_int_equal(
        process_query(
            &server,
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
            &out,
            &out_len),
        0);
    assert_non_null(out);

    uint16_t ancount = (uint16_t)(((uint16_t)out[6] << 8) | out[7]);
    uint16_t arcount = (uint16_t)(((uint16_t)out[10] << 8) | out[11]);
    assert_int_equal(ancount, 1);
    assert_int_equal(arcount, 1);

    size_t q_opt_s = 0;
    size_t q_opt_e = 0;
    size_t r_opt_s = 0;
    size_t r_opt_e = 0;
    assert_int_equal(dns_find_query_opt(DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN, &q_opt_s, &q_opt_e), 0);
    assert_int_equal(dns_find_opt_record(out, out_len, &r_opt_s, &r_opt_e), 0);
    assert_int_equal((int)(r_opt_e - r_opt_s), (int)(q_opt_e - q_opt_s));
    assert_memory_equal(out + r_opt_s, DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS + q_opt_s, q_opt_e - q_opt_s);

    size_t out_q_end = 0;
    assert_int_equal(dns_extract_single_question_name_a(out, out_len, name, sizeof(name), &out_q_end), 0);
    size_t ans = out_q_end;
    assert_int_equal(out[ans + 12], 1);
    assert_int_equal(out[ans + 13], 2);
    assert_int_equal(out[ans + 14], 3);
    assert_int_equal(out[ans + 15], 4);

    free(out);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dns_wire_helpers_branches),
        cmocka_unit_test(test_servfail_and_truncated_builders),
        cmocka_unit_test(test_io_and_socket_helpers),
        cmocka_unit_test(test_process_query_branches),
        cmocka_unit_test(test_tcp_client_loop_large_response_and_zero_length_query),
        cmocka_unit_test(test_dns_server_additional_edge_paths),
        cmocka_unit_test(test_tcp_accept_loop_additional_paths),
        cmocka_unit_test(test_dns_server_socket_and_accept_error_paths),
        cmocka_unit_test(test_dns_server_recv_send_eintr_paths),
        cmocka_unit_test(test_dns_server_tcp_client_error_branches),
        cmocka_unit_test(test_dns_server_udp_loop_truncation_fallback),
        cmocka_unit_test(test_dns_server_udp_truncation_and_servfail_build_fail),
        cmocka_unit_test(test_dns_server_name_skip_steps_limit),
        cmocka_unit_test(test_dns_server_tcp_loop_specific_fail_paths),
        cmocka_unit_test(test_dns_server_udp_loop_poll_and_process_fail_paths),
        cmocka_unit_test(test_proxy_server_init_and_socket_success_paths),
        cmocka_unit_test(test_dns_server_randomized_helper_exploration),
        cmocka_unit_test(test_dns_server_specific_helper_paths),
        cmocka_unit_test(test_udp_loop_and_proxy_run_thread_failure_paths),
        cmocka_unit_test(test_hosts_override_edns_and_parser_edges),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
