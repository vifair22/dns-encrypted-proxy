#include "metrics.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static proxy_metrics_t *g_metrics = NULL;
static atomic_int g_stop = 0;
static pthread_t g_thread;
static int g_thread_started = 0;
static int g_listen_fd = -1;

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int build_metrics_body(const proxy_metrics_t *m, char *out, size_t out_size) {
    if (m == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    int written = snprintf(
        out,
        out_size,
        "doh_proxy_queries_udp_total %llu\n"
        "doh_proxy_queries_tcp_total %llu\n"
        "doh_proxy_cache_hits_total %llu\n"
        "doh_proxy_cache_misses_total %llu\n"
        "doh_proxy_upstream_success_total %llu\n"
        "doh_proxy_upstream_failures_total %llu\n"
        "doh_proxy_servfail_sent_total %llu\n"
        "doh_proxy_truncated_sent_total %llu\n"
        "doh_proxy_tcp_connections_total %llu\n"
        "doh_proxy_tcp_connections_rejected_total %llu\n"
        "doh_proxy_tcp_connections_active %d\n",
        (unsigned long long)atomic_load(&m->queries_udp),
        (unsigned long long)atomic_load(&m->queries_tcp),
        (unsigned long long)atomic_load(&m->cache_hits),
        (unsigned long long)atomic_load(&m->cache_misses),
        (unsigned long long)atomic_load(&m->upstream_success),
        (unsigned long long)atomic_load(&m->upstream_failures),
        (unsigned long long)atomic_load(&m->servfail_sent),
        (unsigned long long)atomic_load(&m->truncated_sent),
        (unsigned long long)atomic_load(&m->tcp_connections_total),
        (unsigned long long)atomic_load(&m->tcp_connections_rejected),
        (int)atomic_load(&m->tcp_connections_active));

    if (written < 0 || (size_t)written >= out_size) {
        return -1;
    }

    return written;
}

static void handle_client(int client_fd) {
    char req[1024];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        return;
    }
    req[n] = '\0';

    const int is_metrics = (strncmp(req, "GET /metrics ", 13) == 0);
    if (!is_metrics) {
        const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)write_all(client_fd, resp, strlen(resp));
        return;
    }

    char body[2048];
    int body_len = build_metrics_body(g_metrics, body, sizeof(body));
    if (body_len < 0) {
        const char *resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)write_all(client_fd, resp, strlen(resp));
        return;
    }

    char header[256];
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        body_len);
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return;
    }

    if (write_all(client_fd, header, (size_t)header_len) != 0) {
        return;
    }
    (void)write_all(client_fd, body, (size_t)body_len);
}

static void *metrics_thread_main(void *arg) {
    (void)arg;

    while (!atomic_load(&g_stop)) {
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = g_listen_fd;
        pfd.events = POLLIN;

        int rc = poll(&pfd, 1, 500);
        if (rc <= 0) {
            continue;
        }
        if ((pfd.revents & POLLIN) == 0) {
            continue;
        }

        int client_fd = accept(g_listen_fd, NULL, NULL);
        if (client_fd < 0) {
            continue;
        }
        handle_client(client_fd);
        close(client_fd);
    }

    return NULL;
}

void metrics_init(proxy_metrics_t *m) {
    if (m == NULL) {
        return;
    }

    atomic_store(&m->queries_udp, 0);
    atomic_store(&m->queries_tcp, 0);
    atomic_store(&m->cache_hits, 0);
    atomic_store(&m->cache_misses, 0);
    atomic_store(&m->upstream_success, 0);
    atomic_store(&m->upstream_failures, 0);
    atomic_store(&m->servfail_sent, 0);
    atomic_store(&m->truncated_sent, 0);
    atomic_store(&m->tcp_connections_total, 0);
    atomic_store(&m->tcp_connections_rejected, 0);
    atomic_store(&m->tcp_connections_active, 0);
}

int metrics_server_start(proxy_metrics_t *m, int port) {
    if (m == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int reuse = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 32) != 0) {
        close(fd);
        return -1;
    }

    g_metrics = m;
    g_listen_fd = fd;
    atomic_store(&g_stop, 0);

    if (pthread_create(&g_thread, NULL, metrics_thread_main, NULL) != 0) {
        close(fd);
        g_listen_fd = -1;
        g_metrics = NULL;
        return -1;
    }

    g_thread_started = 1;
    return 0;
}

void metrics_server_stop(void) {
    atomic_store(&g_stop, 1);

    if (g_listen_fd >= 0) {
        shutdown(g_listen_fd, SHUT_RDWR);
        close(g_listen_fd);
        g_listen_fd = -1;
    }

    if (g_thread_started) {
        pthread_join(g_thread, NULL);
        g_thread_started = 0;
    }

    g_metrics = NULL;
}
