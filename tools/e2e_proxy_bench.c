#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int protocol; /* 0=udp,1=tcp,2=udp-upgrade */
    size_t requests;
    size_t concurrency;
    size_t warmup;
    int timeout_ms;
    int upstream_delay_us;
    int upstream_answer_count;
    const char *proxy_bin;
} bench_opts_t;

typedef struct {
    int proxy_port;
    int protocol;
    int timeout_ms;
    atomic_size_t *next_idx;
    size_t requests;
    uint64_t *lat_ns;
    atomic_size_t *ok_count;
    atomic_size_t *fail_count;
} worker_args_t;

enum {
    PROTO_UDP = 0,
    PROTO_TCP = 1,
    PROTO_UDP_UPGRADE = 2,
};

static const uint8_t DNS_QUERY_EXAMPLE_A[] = {
    0x12, 0x34, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x07, 'e',  'x',  'a',
    'm',  'p',  'l',  'e',
    0x03, 'c',  'o',  'm',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int reserve_local_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    socklen_t len = (socklen_t)sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }

    int port = (int)ntohs(addr.sin_port);
    close(fd);
    return port;
}

static int wait_tcp_listen(int port, int timeout_ms) {
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ULL;
    while (now_ns() < deadline) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)port);

        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);
        if (rc == 0) {
            return 0;
        }

        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

static int send_one_udp_query(int proxy_port, int timeout_ms, uint16_t dns_id, uint64_t *lat_out_ns) {
    /* Measures full client-observed UDP round trip: sendto -> recv. */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)proxy_port);

    uint8_t query[sizeof(DNS_QUERY_EXAMPLE_A)];
    memcpy(query, DNS_QUERY_EXAMPLE_A, sizeof(query));
    query[0] = (uint8_t)((dns_id >> 8) & 0xFFu);
    query[1] = (uint8_t)(dns_id & 0xFFu);

    uint64_t t0 = now_ns();
    ssize_t sent = sendto(fd, query, sizeof(query), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent != (ssize_t)sizeof(query)) {
        close(fd);
        return -1;
    }

    uint8_t resp[2048];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    uint64_t t1 = now_ns();
    close(fd);

    if (n < 12) {
        return -1;
    }
    uint16_t got_id = (uint16_t)(((uint16_t)resp[0] << 8) | (uint16_t)resp[1]);
    if (got_id != dns_id) {
        return -1;
    }

    if (lat_out_ns != NULL) {
        *lat_out_ns = t1 - t0;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
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

static int send_one_tcp_query(int proxy_port, int timeout_ms, uint16_t dns_id, uint64_t *lat_out_ns) {
    /*
     * This mode intentionally opens a new TCP connection per query to model
     * short-lived clients and expose handshake/setup cost explicitly.
     */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)proxy_port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    uint8_t query[sizeof(DNS_QUERY_EXAMPLE_A)];
    memcpy(query, DNS_QUERY_EXAMPLE_A, sizeof(query));
    query[0] = (uint8_t)((dns_id >> 8) & 0xFFu);
    query[1] = (uint8_t)(dns_id & 0xFFu);

    uint8_t frame_hdr[2] = {
        (uint8_t)((sizeof(query) >> 8) & 0xFFu),
        (uint8_t)(sizeof(query) & 0xFFu),
    };

    uint64_t t0 = now_ns();
    if (send_all(fd, frame_hdr, sizeof(frame_hdr)) != 0 || send_all(fd, query, sizeof(query)) != 0) {
        close(fd);
        return -1;
    }

    uint8_t len_buf[2];
    if (recv_all(fd, len_buf, 2) != 0) {
        close(fd);
        return -1;
    }

    uint16_t resp_len = (uint16_t)(((uint16_t)len_buf[0] << 8) | (uint16_t)len_buf[1]);
    if (resp_len < 12) {
        close(fd);
        return -1;
    }

    uint8_t *resp = malloc(resp_len);
    if (resp == NULL) {
        close(fd);
        return -1;
    }
    int rc = recv_all(fd, resp, resp_len);
    uint64_t t1 = now_ns();
    close(fd);
    if (rc != 0) {
        free(resp);
        return -1;
    }

    uint16_t got_id = (uint16_t)(((uint16_t)resp[0] << 8) | (uint16_t)resp[1]);
    free(resp);
    if (got_id != dns_id) {
        return -1;
    }

    if (lat_out_ns != NULL) {
        *lat_out_ns = t1 - t0;
    }
    return 0;
}

static int send_one_udp_upgrade_query(int proxy_port, int timeout_ms, uint16_t dns_id, uint64_t *lat_out_ns) {
    /*
     * Upgrade path latency includes both phases:
     *  1) UDP query receiving TC=1
     *  2) TCP retry of the same DNS message
     */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)proxy_port);

    uint8_t query[sizeof(DNS_QUERY_EXAMPLE_A)];
    memcpy(query, DNS_QUERY_EXAMPLE_A, sizeof(query));
    query[0] = (uint8_t)((dns_id >> 8) & 0xFFu);
    query[1] = (uint8_t)(dns_id & 0xFFu);

    uint64_t t0 = now_ns();
    ssize_t sent = sendto(fd, query, sizeof(query), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent != (ssize_t)sizeof(query)) {
        close(fd);
        return -1;
    }

    uint8_t resp[2048];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);
    if (n < 12) {
        return -1;
    }

    uint16_t got_id = (uint16_t)(((uint16_t)resp[0] << 8) | (uint16_t)resp[1]);
    if (got_id != dns_id) {
        return -1;
    }

    uint16_t flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    if ((flags & 0x0200u) == 0) {
        return -1;
    }

    uint64_t tail = 0;
    if (send_one_tcp_query(proxy_port, timeout_ms, dns_id, &tail) != 0) {
        return -1;
    }

    if (lat_out_ns != NULL) {
        uint64_t t1 = now_ns();
        *lat_out_ns = t1 - t0;
    }
    return 0;
}

static int wait_proxy_ready(int proxy_port, int timeout_ms) {
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ULL;
    while (now_ns() < deadline) {
        if (send_one_udp_query(proxy_port, 250, 0xBEEF, NULL) == 0) {
            return 0;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

static int write_proxy_config(const char *path, int proxy_port, int upstream_port) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    int n = fprintf(
        fp,
        "listen_addr=127.0.0.1\n"
        "listen_port=%d\n"
        "upstream_timeout_ms=1500\n"
        "upstream_pool_size=4\n"
        "cache_capacity=4096\n"
        "upstreams=https://127.0.0.1:%d/dns-query\n"
        "metrics_enabled=0\n"
        "metrics_port=9090\n"
        "tcp_idle_timeout_ms=10000\n"
        "tcp_max_clients=256\n"
        "tcp_max_queries_per_conn=0\n",
        proxy_port,
        upstream_port);

    fclose(fp);
    return n > 0 ? 0 : -1;
}

static pid_t spawn_mock_upstream(int port, int delay_us, int answer_count) {
    char port_s[32];
    char delay_s[32];
    char answers_s[32];
    snprintf(port_s, sizeof(port_s), "%d", port);
    snprintf(delay_s, sizeof(delay_s), "%d", delay_us);
    snprintf(answers_s, sizeof(answers_s), "%d", answer_count);

    pid_t pid = fork();
    if (pid != 0) {
        return pid;
    }

    execlp(
        "python3",
        "python3",
        "tools/mock_doh_server.py",
        "--host",
        "127.0.0.1",
        "--port",
        port_s,
        "--cert",
        "tests/certs/localhost.cert.pem",
        "--key",
        "tests/certs/localhost.key.pem",
        "--delay-us",
        delay_s,
        "--answer-count",
        answers_s,
        (char *)NULL);

    _exit(127);
}

static pid_t spawn_proxy(const char *proxy_bin, const char *cfg_path) {
    pid_t pid = fork();
    if (pid != 0) {
        return pid;
    }

    setenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS", "1", 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1", "1", 1);
    execl(proxy_bin, proxy_bin, cfg_path, (char *)NULL);
    _exit(127);
}

static void stop_process(pid_t pid) {
    if (pid <= 0) {
        return;
    }
    kill(pid, SIGTERM);
    for (int i = 0; i < 40; i++) {
        int status = 0;
        pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid) {
            return;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t percentile_ns(const uint64_t *vals, size_t n, double pct) {
    if (n == 0) {
        return 0;
    }
    double pos = (pct / 100.0) * (double)(n - 1);
    size_t idx = (size_t)(pos + 0.5);
    if (idx >= n) {
        idx = n - 1;
    }
    return vals[idx];
}

static void *worker_main(void *arg) {
    worker_args_t *w = (worker_args_t *)arg;
    while (1) {
        size_t idx = atomic_fetch_add(w->next_idx, 1);
        if (idx >= w->requests) {
            break;
        }

        uint64_t lat = 0;
        uint16_t id = (uint16_t)((idx % 65535u) + 1u);
        /* Keep worker logic protocol-neutral so load generation is consistent. */
        int rc = -1;
        if (w->protocol == PROTO_UDP) {
            rc = send_one_udp_query(w->proxy_port, w->timeout_ms, id, &lat);
        } else if (w->protocol == PROTO_TCP) {
            rc = send_one_tcp_query(w->proxy_port, w->timeout_ms, id, &lat);
        } else {
            rc = send_one_udp_upgrade_query(w->proxy_port, w->timeout_ms, id, &lat);
        }

        if (rc == 0) {
            w->lat_ns[idx] = lat;
            atomic_fetch_add(w->ok_count, 1);
        } else {
            w->lat_ns[idx] = 0;
            atomic_fetch_add(w->fail_count, 1);
        }
    }
    return NULL;
}

static void print_usage(const char *argv0) {
    printf(
        "Usage: %s [--protocol udp|tcp|udp-upgrade] [--requests N] [--concurrency N] [--warmup N] [--timeout-ms N] [--upstream-delay-us N] [--upstream-answer-count N] [--proxy-bin PATH]\n",
        argv0);
}

static int parse_opts(int argc, char **argv, bench_opts_t *opts) {
    opts->requests = 20000;
    opts->concurrency = 32;
    opts->warmup = 1000;
    opts->timeout_ms = 2000;
    opts->upstream_delay_us = 0;
    opts->upstream_answer_count = 1;
    opts->protocol = PROTO_UDP;
    opts->proxy_bin = "./build/dns-encrypted-proxy";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--protocol") == 0 && i + 1 < argc) {
            const char *p = argv[++i];
            if (strcmp(p, "udp") == 0) {
                opts->protocol = PROTO_UDP;
            } else if (strcmp(p, "tcp") == 0) {
                opts->protocol = PROTO_TCP;
            } else if (strcmp(p, "udp-upgrade") == 0) {
                opts->protocol = PROTO_UDP_UPGRADE;
                if (opts->upstream_answer_count < 40) {
                    opts->upstream_answer_count = 40;
                }
            } else {
                return -1;
            }
        } else if (strcmp(argv[i], "--requests") == 0 && i + 1 < argc) {
            opts->requests = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            opts->concurrency = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            opts->warmup = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            opts->timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--upstream-delay-us") == 0 && i + 1 < argc) {
            opts->upstream_delay_us = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--upstream-answer-count") == 0 && i + 1 < argc) {
            opts->upstream_answer_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--proxy-bin") == 0 && i + 1 < argc) {
            opts->proxy_bin = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    if (opts->requests == 0 || opts->concurrency == 0 || opts->timeout_ms <= 0 || opts->upstream_answer_count <= 0) {
        return -1;
    }
    if (opts->protocol == PROTO_UDP_UPGRADE && opts->upstream_answer_count < 40) {
        opts->upstream_answer_count = 40;
    }
    return 0;
}

int main(int argc, char **argv) {
    bench_opts_t opts;
    int p = parse_opts(argc, argv, &opts);
    if (p != 0) {
        return p < 0 ? 2 : 0;
    }

    int upstream_port = reserve_local_port();
    int proxy_port = reserve_local_port();
    if (upstream_port <= 0 || proxy_port <= 0) {
        fprintf(stderr, "failed to reserve ports\n");
        return 1;
    }

    char cfg_path[] = "/tmp/dns_encrypted_proxy_bench_cfg_XXXXXX";
    int cfg_fd = mkstemp(cfg_path);
    if (cfg_fd < 0) {
        perror("mkstemp");
        return 1;
    }
    close(cfg_fd);
    if (write_proxy_config(cfg_path, proxy_port, upstream_port) != 0) {
        fprintf(stderr, "failed to write config\n");
        unlink(cfg_path);
        return 1;
    }

    pid_t upstream_pid = spawn_mock_upstream(upstream_port, opts.upstream_delay_us, opts.upstream_answer_count);
    if (upstream_pid <= 0 || wait_tcp_listen(upstream_port, 5000) != 0) {
        fprintf(stderr, "failed to start mock upstream\n");
        stop_process(upstream_pid);
        unlink(cfg_path);
        return 1;
    }

    pid_t proxy_pid = spawn_proxy(opts.proxy_bin, cfg_path);
    if (proxy_pid <= 0 || wait_proxy_ready(proxy_port, 8000) != 0) {
        fprintf(stderr, "failed to start proxy\n");
        stop_process(proxy_pid);
        stop_process(upstream_pid);
        unlink(cfg_path);
        return 1;
    }

    for (size_t i = 0; i < opts.warmup; i++) {
        uint16_t id = (uint16_t)(0x9000u + (i % 1000u));
        if (opts.protocol == PROTO_UDP) {
            (void)send_one_udp_query(proxy_port, opts.timeout_ms, id, NULL);
        } else if (opts.protocol == PROTO_TCP) {
            (void)send_one_tcp_query(proxy_port, opts.timeout_ms, id, NULL);
        } else {
            (void)send_one_udp_upgrade_query(proxy_port, opts.timeout_ms, id, NULL);
        }
    }

    uint64_t *lat_ns = calloc(opts.requests, sizeof(*lat_ns));
    pthread_t *threads = calloc(opts.concurrency, sizeof(*threads));
    worker_args_t *args = calloc(opts.concurrency, sizeof(*args));
    if (lat_ns == NULL || threads == NULL || args == NULL) {
        fprintf(stderr, "allocation failure\n");
        free(lat_ns);
        free(threads);
        free(args);
        stop_process(proxy_pid);
        stop_process(upstream_pid);
        unlink(cfg_path);
        return 1;
    }

    atomic_size_t next_idx;
    atomic_init(&next_idx, 0);
    atomic_size_t ok_count;
    atomic_init(&ok_count, 0);
    atomic_size_t fail_count;
    atomic_init(&fail_count, 0);

    uint64_t t0 = now_ns();
    for (size_t i = 0; i < opts.concurrency; i++) {
        args[i].proxy_port = proxy_port;
        args[i].protocol = opts.protocol;
        args[i].timeout_ms = opts.timeout_ms;
        args[i].next_idx = &next_idx;
        args[i].requests = opts.requests;
        args[i].lat_ns = lat_ns;
        args[i].ok_count = &ok_count;
        args[i].fail_count = &fail_count;
        if (pthread_create(&threads[i], NULL, worker_main, &args[i]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            opts.concurrency = i;
            break;
        }
    }

    for (size_t i = 0; i < opts.concurrency; i++) {
        pthread_join(threads[i], NULL);
    }
    uint64_t t1 = now_ns();

    size_t ok = atomic_load(&ok_count);
    size_t fail = atomic_load(&fail_count);
    double sec = (double)(t1 - t0) / 1e9;
    double rps = sec > 0.0 ? (double)opts.requests / sec : 0.0;

    uint64_t *succ = calloc(ok, sizeof(*succ));
    size_t si = 0;
    for (size_t i = 0; i < opts.requests; i++) {
        if (lat_ns[i] > 0 && si < ok) {
            succ[si++] = lat_ns[i];
        }
    }

    if (si > 0) {
        qsort(succ, si, sizeof(*succ), cmp_u64);
    }

    uint64_t p50 = percentile_ns(succ, si, 50.0);
    uint64_t p95 = percentile_ns(succ, si, 95.0);
    uint64_t p99 = percentile_ns(succ, si, 99.0);
    uint64_t pmax = si > 0 ? succ[si - 1] : 0;

    const char *proto_name = opts.protocol == PROTO_UDP
                                 ? "udp"
                                 : (opts.protocol == PROTO_TCP ? "tcp" : "udp-upgrade");
    printf("e2e_proxy_bench\n");
    printf("  protocol=%s requests=%zu concurrency=%zu warmup=%zu timeout_ms=%d upstream_delay_us=%d upstream_answer_count=%d\n", proto_name, opts.requests, opts.concurrency, opts.warmup, opts.timeout_ms, opts.upstream_delay_us, opts.upstream_answer_count);
    printf("  proxy_port=%d upstream_port=%d\n", proxy_port, upstream_port);
    printf("  completed=%zu failed=%zu error_rate=%.2f%%\n", ok, fail, opts.requests > 0 ? (100.0 * (double)fail / (double)opts.requests) : 0.0);
    printf("  duration=%.3fs throughput=%.0f req/s\n", sec, rps);
    printf("  latency_us p50=%.2f p95=%.2f p99=%.2f max=%.2f\n", p50 / 1000.0, p95 / 1000.0, p99 / 1000.0, pmax / 1000.0);

    free(succ);
    free(lat_ns);
    free(threads);
    free(args);

    stop_process(proxy_pid);
    stop_process(upstream_pid);
    unlink(cfg_path);
    return fail > 0 ? 3 : 0;
}
