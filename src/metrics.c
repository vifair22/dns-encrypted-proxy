#define _POSIX_C_SOURCE 200809L

#include "metrics.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static proxy_metrics_t *g_metrics = NULL;
static dns_cache_t *g_cache = NULL;
static upstream_client_t *g_upstream = NULL;
static uint64_t g_start_monotonic_ms = 0;
static atomic_int g_stop = 0;
static pthread_t g_thread;
static int g_thread_started = 0;
static int g_listen_fd = -1;

static uint64_t now_monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

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

static int appendf(char *out, size_t out_size, size_t *offset, const char *fmt, ...) {
    if (out == NULL || offset == NULL || fmt == NULL || *offset >= out_size) {
        return -1;
    }

    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf(out + *offset, out_size - *offset, fmt, ap);
    va_end(ap);

    if (written < 0 || (size_t)written >= (out_size - *offset)) {
        return -1;
    }

    *offset += (size_t)written;
    return 0;
}

static const char *upstream_protocol_label(upstream_type_t type) {
    return (type == UPSTREAM_TYPE_DOT) ? "dot" : "doh";
}

static void escape_label_value(const char *src, char *dst, size_t dst_size) {
    if (dst == NULL || dst_size == 0) {
        return;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return;
    }

    size_t out = 0;
    for (size_t i = 0; src[i] != '\0' && out + 1 < dst_size; i++) {
        char c = src[i];
        if (c == '\\' || c == '"') {
            if (out + 2 >= dst_size) {
                break;
            }
            dst[out++] = '\\';
            dst[out++] = c;
            continue;
        }
        if (c == '\n') {
            if (out + 2 >= dst_size) {
                break;
            }
            dst[out++] = '\\';
            dst[out++] = 'n';
            continue;
        }
        dst[out++] = c;
    }
    dst[out] = '\0';
}

static int append_upstream_metrics(char *out, size_t out_size, size_t *offset) {
    if (appendf(out, out_size, offset,
                "# HELP doh_proxy_upstream_server_requests_total Total requests attempted against each configured upstream.\n"
                "# TYPE doh_proxy_upstream_server_requests_total counter\n"
                "# HELP doh_proxy_upstream_server_failures_total Total failed requests against each configured upstream.\n"
                "# TYPE doh_proxy_upstream_server_failures_total counter\n"
                "# HELP doh_proxy_upstream_server_healthy Upstream health state (1 healthy, 0 unhealthy).\n"
                "# TYPE doh_proxy_upstream_server_healthy gauge\n"
                "# HELP doh_proxy_upstream_server_consecutive_failures Consecutive failure count per upstream.\n"
                "# TYPE doh_proxy_upstream_server_consecutive_failures gauge\n") != 0) {
        return -1;
    }

    if (g_upstream == NULL) {
        return 0;
    }

    for (int i = 0; i < g_upstream->server_count; i++) {
        const upstream_server_t *server = &g_upstream->servers[i];
        char escaped_url[2048];
        escape_label_value(server->url, escaped_url, sizeof(escaped_url));

        if (appendf(out,
                    out_size,
                    offset,
                    "doh_proxy_upstream_server_requests_total{upstream=\"%s\",protocol=\"%s\"} %llu\n"
                    "doh_proxy_upstream_server_failures_total{upstream=\"%s\",protocol=\"%s\"} %llu\n"
                    "doh_proxy_upstream_server_healthy{upstream=\"%s\",protocol=\"%s\"} %d\n"
                    "doh_proxy_upstream_server_consecutive_failures{upstream=\"%s\",protocol=\"%s\"} %u\n",
                    escaped_url,
                    upstream_protocol_label(server->type),
                    (unsigned long long)server->health.total_queries,
                    escaped_url,
                    upstream_protocol_label(server->type),
                    (unsigned long long)server->health.total_failures,
                    escaped_url,
                    upstream_protocol_label(server->type),
                    server->health.healthy ? 1 : 0,
                    escaped_url,
                    upstream_protocol_label(server->type),
                    (unsigned int)server->health.consecutive_failures) != 0) {
            return -1;
        }
    }

    return 0;
}

static int build_metrics_body(const proxy_metrics_t *m, char *out, size_t out_size) {
    if (m == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    size_t cache_capacity = 0;
    size_t cache_entries = 0;
    uint64_t cache_evictions = 0;
    uint64_t cache_expirations = 0;
    size_t cache_bytes_in_use = 0;
    if (g_cache != NULL) {
        dns_cache_get_stats(g_cache, &cache_capacity, &cache_entries);
        dns_cache_get_counters(g_cache, &cache_evictions, &cache_expirations, &cache_bytes_in_use);
    }

    uint64_t now_ms = now_monotonic_ms();
    double uptime_seconds = 0.0;
    if (g_start_monotonic_ms > 0 && now_ms >= g_start_monotonic_ms) {
        uptime_seconds = (double)(now_ms - g_start_monotonic_ms) / 1000.0;
    }

    uint64_t rcode_other = 0;
    for (size_t i = 0; i < 16; i++) {
        if (i == 0 || i == 2 || i == 3 || i == 5) {
            continue;
        }
        rcode_other += (uint64_t)atomic_load(&m->responses_rcode[i]);
    }

    upstream_runtime_stats_t runtime_stats;
    (void)upstream_get_runtime_stats(g_upstream, &runtime_stats);
    int doh_pool_idle = runtime_stats.doh_pool_capacity - runtime_stats.doh_pool_in_use;
    int dot_pool_idle = runtime_stats.dot_pool_capacity - runtime_stats.dot_pool_in_use;
    if (doh_pool_idle < 0) {
        doh_pool_idle = 0;
    }
    if (dot_pool_idle < 0) {
        dot_pool_idle = 0;
    }

    size_t offset = 0;
    if (appendf(
            out,
            out_size,
            &offset,
            "# HELP doh_proxy_uptime_seconds Process uptime in seconds.\n"
            "# TYPE doh_proxy_uptime_seconds gauge\n"
            "doh_proxy_uptime_seconds %.3f\n"
            "# HELP doh_proxy_queries_udp_total Total number of DNS queries received over UDP.\n"
            "# TYPE doh_proxy_queries_udp_total counter\n"
            "doh_proxy_queries_udp_total %llu\n"
            "# HELP doh_proxy_queries_tcp_total Total number of DNS queries received over TCP.\n"
            "# TYPE doh_proxy_queries_tcp_total counter\n"
            "doh_proxy_queries_tcp_total %llu\n"
            "# HELP doh_proxy_cache_hits_total Total number of cache hits.\n"
            "# TYPE doh_proxy_cache_hits_total counter\n"
            "doh_proxy_cache_hits_total %llu\n"
            "# HELP doh_proxy_cache_misses_total Total number of cache misses.\n"
            "# TYPE doh_proxy_cache_misses_total counter\n"
            "doh_proxy_cache_misses_total %llu\n"
            "# HELP doh_proxy_upstream_success_total Total number of successful upstream resolutions.\n"
            "# TYPE doh_proxy_upstream_success_total counter\n"
            "doh_proxy_upstream_success_total %llu\n"
            "# HELP doh_proxy_upstream_failures_total Total number of failed upstream resolutions.\n"
            "# TYPE doh_proxy_upstream_failures_total counter\n"
            "doh_proxy_upstream_failures_total %llu\n"
            "# HELP doh_proxy_servfail_sent_total Total number of SERVFAIL responses sent by the proxy.\n"
            "# TYPE doh_proxy_servfail_sent_total counter\n"
            "doh_proxy_servfail_sent_total %llu\n"
            "# HELP doh_proxy_truncated_sent_total Total number of truncated UDP responses sent.\n"
            "# TYPE doh_proxy_truncated_sent_total counter\n"
            "doh_proxy_truncated_sent_total %llu\n"
            "# HELP doh_proxy_tcp_connections_total Total number of accepted TCP client connections.\n"
            "# TYPE doh_proxy_tcp_connections_total counter\n"
            "doh_proxy_tcp_connections_total %llu\n"
            "# HELP doh_proxy_tcp_connections_rejected_total Total number of rejected TCP client connections.\n"
            "# TYPE doh_proxy_tcp_connections_rejected_total counter\n"
            "doh_proxy_tcp_connections_rejected_total %llu\n"
            "# HELP doh_proxy_tcp_connections_active Number of currently active TCP client connections.\n"
            "# TYPE doh_proxy_tcp_connections_active gauge\n"
            "doh_proxy_tcp_connections_active %d\n"
            "# HELP doh_proxy_responses_total Total number of DNS responses sent by the proxy.\n"
            "# TYPE doh_proxy_responses_total counter\n"
            "doh_proxy_responses_total %llu\n"
            "# HELP doh_proxy_responses_rcode_total Total number of DNS responses by RCODE.\n"
            "# TYPE doh_proxy_responses_rcode_total counter\n"
            "doh_proxy_responses_rcode_total{rcode=\"NOERROR\"} %llu\n"
            "doh_proxy_responses_rcode_total{rcode=\"SERVFAIL\"} %llu\n"
            "doh_proxy_responses_rcode_total{rcode=\"NXDOMAIN\"} %llu\n"
            "doh_proxy_responses_rcode_total{rcode=\"REFUSED\"} %llu\n"
            "doh_proxy_responses_rcode_total{rcode=\"OTHER\"} %llu\n"
            "# HELP doh_proxy_cache_entries Number of cache entries currently in use.\n"
            "# TYPE doh_proxy_cache_entries gauge\n"
            "doh_proxy_cache_entries %llu\n"
            "# HELP doh_proxy_cache_capacity Total configured cache entry capacity.\n"
            "# TYPE doh_proxy_cache_capacity gauge\n"
            "doh_proxy_cache_capacity %llu\n"
            "# HELP doh_proxy_cache_evictions_total Total cache evictions due to capacity pressure.\n"
            "# TYPE doh_proxy_cache_evictions_total counter\n"
            "doh_proxy_cache_evictions_total %llu\n"
            "# HELP doh_proxy_cache_expirations_total Total cache entries expired and removed.\n"
            "# TYPE doh_proxy_cache_expirations_total counter\n"
            "doh_proxy_cache_expirations_total %llu\n"
            "# HELP doh_proxy_cache_bytes_in_use Approximate bytes currently held by cache key/value payloads.\n"
            "# TYPE doh_proxy_cache_bytes_in_use gauge\n"
            "doh_proxy_cache_bytes_in_use %llu\n"
            "# HELP doh_proxy_metrics_http_requests_total Total HTTP requests received by the metrics endpoint.\n"
            "# TYPE doh_proxy_metrics_http_requests_total counter\n"
            "doh_proxy_metrics_http_requests_total %llu\n"
            "# HELP doh_proxy_metrics_http_responses_total Total HTTP responses returned by status code class.\n"
            "# TYPE doh_proxy_metrics_http_responses_total counter\n"
            "doh_proxy_metrics_http_responses_total{code_class=\"2xx\"} %llu\n"
            "doh_proxy_metrics_http_responses_total{code_class=\"4xx\"} %llu\n"
            "doh_proxy_metrics_http_responses_total{code_class=\"5xx\"} %llu\n"
            "# HELP doh_proxy_metrics_http_in_flight Number of in-flight HTTP metrics requests.\n"
            "# TYPE doh_proxy_metrics_http_in_flight gauge\n"
            "doh_proxy_metrics_http_in_flight %d\n",
            uptime_seconds,
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
            (int)atomic_load(&m->tcp_connections_active),
            (unsigned long long)atomic_load(&m->responses_total),
            (unsigned long long)atomic_load(&m->responses_rcode[0]),
            (unsigned long long)atomic_load(&m->responses_rcode[2]),
            (unsigned long long)atomic_load(&m->responses_rcode[3]),
            (unsigned long long)atomic_load(&m->responses_rcode[5]),
            (unsigned long long)rcode_other,
            (unsigned long long)cache_entries,
            (unsigned long long)cache_capacity,
            (unsigned long long)cache_evictions,
            (unsigned long long)cache_expirations,
            (unsigned long long)cache_bytes_in_use,
            (unsigned long long)atomic_load(&m->metrics_http_requests_total),
            (unsigned long long)atomic_load(&m->metrics_http_responses_2xx_total),
            (unsigned long long)atomic_load(&m->metrics_http_responses_4xx_total),
            (unsigned long long)atomic_load(&m->metrics_http_responses_5xx_total),
            (int)atomic_load(&m->metrics_http_in_flight)) != 0) {
        return -1;
    }

    if (appendf(
            out,
            out_size,
            &offset,
            "# HELP doh_proxy_doh_pool_capacity Configured DoH handle pool capacity.\n"
            "# TYPE doh_proxy_doh_pool_capacity gauge\n"
            "doh_proxy_doh_pool_capacity %d\n"
            "# HELP doh_proxy_doh_pool_in_use Number of DoH handles currently in use.\n"
            "# TYPE doh_proxy_doh_pool_in_use gauge\n"
            "doh_proxy_doh_pool_in_use %d\n"
            "# HELP doh_proxy_doh_pool_idle Number of idle DoH handles in pool.\n"
            "# TYPE doh_proxy_doh_pool_idle gauge\n"
            "doh_proxy_doh_pool_idle %d\n"
            "# HELP doh_proxy_doh_http_responses_total Total DoH responses by negotiated HTTP version.\n"
            "# TYPE doh_proxy_doh_http_responses_total counter\n"
            "doh_proxy_doh_http_responses_total{version=\"h2\"} %llu\n"
            "doh_proxy_doh_http_responses_total{version=\"h1\"} %llu\n"
            "doh_proxy_doh_http_responses_total{version=\"other\"} %llu\n"
            "# HELP doh_proxy_dot_pool_capacity Configured DoT connection pool capacity.\n"
            "# TYPE doh_proxy_dot_pool_capacity gauge\n"
            "doh_proxy_dot_pool_capacity %d\n"
            "# HELP doh_proxy_dot_pool_in_use Number of DoT connection slots currently in use.\n"
            "# TYPE doh_proxy_dot_pool_in_use gauge\n"
            "doh_proxy_dot_pool_in_use %d\n"
            "# HELP doh_proxy_dot_pool_idle Number of idle DoT connection slots in pool.\n"
            "# TYPE doh_proxy_dot_pool_idle gauge\n"
            "doh_proxy_dot_pool_idle %d\n"
            "# HELP doh_proxy_dot_connections_alive Number of currently established DoT TLS connections.\n"
            "# TYPE doh_proxy_dot_connections_alive gauge\n"
            "doh_proxy_dot_connections_alive %d\n",
            runtime_stats.doh_pool_capacity,
            runtime_stats.doh_pool_in_use,
            doh_pool_idle,
            (unsigned long long)runtime_stats.doh_http2_responses_total,
            (unsigned long long)runtime_stats.doh_http1_responses_total,
            (unsigned long long)runtime_stats.doh_http_other_responses_total,
            runtime_stats.dot_pool_capacity,
            runtime_stats.dot_pool_in_use,
            dot_pool_idle,
            runtime_stats.dot_connections_alive) != 0) {
        return -1;
    }

    if (append_upstream_metrics(out, out_size, &offset) != 0) {
        return -1;
    }

    return (int)offset;
}

static void handle_client(int client_fd) {
    char req[1024];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        return;
    }
    req[n] = '\0';

    int tracked = 0;
    if (g_metrics != NULL) {
        atomic_fetch_add(&g_metrics->metrics_http_requests_total, 1);
        atomic_fetch_add(&g_metrics->metrics_http_in_flight, 1);
        tracked = 1;
    }

    const int is_metrics = (strncmp(req, "GET /metrics ", 13) == 0);
    if (!is_metrics) {
        const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)write_all(client_fd, resp, strlen(resp));
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_4xx_total, 1);
        }
        goto done;
    }

    char body[32768];
    int body_len = build_metrics_body(g_metrics, body, sizeof(body));
    if (body_len < 0) {
        const char *resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)write_all(client_fd, resp, strlen(resp));
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
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
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
    }

    if (write_all(client_fd, header, (size_t)header_len) != 0) {
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
    }

    if (write_all(client_fd, body, (size_t)body_len) == 0) {
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_2xx_total, 1);
        }
    } else if (g_metrics != NULL) {
        atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
    }

done:
    if (tracked) {
        atomic_fetch_sub(&g_metrics->metrics_http_in_flight, 1);
    }
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
    atomic_store(&m->responses_total, 0);
    for (size_t i = 0; i < 16; i++) {
        atomic_store(&m->responses_rcode[i], 0);
    }
    atomic_store(&m->metrics_http_requests_total, 0);
    atomic_store(&m->metrics_http_responses_2xx_total, 0);
    atomic_store(&m->metrics_http_responses_4xx_total, 0);
    atomic_store(&m->metrics_http_responses_5xx_total, 0);
    atomic_store(&m->metrics_http_in_flight, 0);
}

int metrics_server_start(proxy_metrics_t *m, dns_cache_t *cache, upstream_client_t *upstream, int port) {
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
    g_cache = cache;
    g_upstream = upstream;
    g_start_monotonic_ms = now_monotonic_ms();
    g_listen_fd = fd;
    atomic_store(&g_stop, 0);

    if (pthread_create(&g_thread, NULL, metrics_thread_main, NULL) != 0) {
        close(fd);
        g_listen_fd = -1;
        g_metrics = NULL;
        g_cache = NULL;
        g_upstream = NULL;
        g_start_monotonic_ms = 0;
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
    g_cache = NULL;
    g_upstream = NULL;
    g_start_monotonic_ms = 0;
}
