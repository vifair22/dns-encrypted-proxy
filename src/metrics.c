#define _POSIX_C_SOURCE 200809L

#include "metrics.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static proxy_metrics_t *g_metrics = NULL;
static dns_cache_t *g_cache = NULL;
static upstream_client_t *g_upstream = NULL;
static upstream_facilitator_t *g_facilitator = NULL;
static uint64_t g_start_monotonic_ms = 0;
static uint64_t g_prev_process_cpu_wall_ms = 0;
static double g_prev_process_cpu_seconds = 0.0;
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

static int read_process_cpu_seconds(double *cpu_seconds_out) {
    if (cpu_seconds_out == NULL) {
        return -1;
    }

    FILE *fp = fopen("/proc/self/stat", "r");
    if (fp == NULL) {
        return -1;
    }

    char line[4096];
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char *rparen = strrchr(line, ')');
    if (rparen == NULL || rparen[1] == '\0') {
        return -1;
    }

    char *cursor = rparen + 2;
    int field = 3;
    uint64_t utime_ticks = 0;
    uint64_t stime_ticks = 0;

    while (*cursor != '\0') {
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        char *end = cursor;
        while (*end != '\0' && *end != ' ') {
            end++;
        }

        if (field == 14 || field == 15) {
            char saved = *end;
            *end = '\0';
            unsigned long long ticks = strtoull(cursor, NULL, 10);
            *end = saved;
            if (field == 14) {
                utime_ticks = (uint64_t)ticks;
            } else {
                stime_ticks = (uint64_t)ticks;
                break;
            }
        }

        if (*end == '\0') {
            break;
        }
        cursor = end + 1;
        field++;
    }

    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0) {
        return -1;
    }

    *cpu_seconds_out = (double)(utime_ticks + stime_ticks) / (double)hz;
    return 0;
}

static int read_process_rss_bytes(uint64_t *rss_bytes_out) {
    if (rss_bytes_out == NULL) {
        return -1;
    }

    FILE *fp = fopen("/proc/self/statm", "r");
    if (fp == NULL) {
        return -1;
    }

    unsigned long total_pages = 0;
    unsigned long rss_pages = 0;
    int rc = fscanf(fp, "%lu %lu", &total_pages, &rss_pages);
    fclose(fp);
    if (rc != 2) {
        return -1;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return -1;
    }

    *rss_bytes_out = (uint64_t)rss_pages * (uint64_t)page_size;
    return 0;
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
    switch (type) {
        case UPSTREAM_TYPE_DOT:
            return "dot";
        case UPSTREAM_TYPE_DOQ:
            return "doq";
        case UPSTREAM_TYPE_DOH:
        default:
            return "doh";
    }
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
    /*
     * Keep label escaping local and bounded to avoid malformed exposition or
     * accidental metric-cardinality explosions from raw upstream strings.
     */
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
                "\n"
                "# ---- upstream servers ----\n"
                "# HELP dns_encrypted_proxy_upstream_server_requests_total Total requests attempted against each configured upstream.\n"
                "# TYPE dns_encrypted_proxy_upstream_server_requests_total counter\n"
                "# HELP dns_encrypted_proxy_upstream_server_failures_total Total failed requests against each configured upstream.\n"
                "# TYPE dns_encrypted_proxy_upstream_server_failures_total counter\n"
                "# HELP dns_encrypted_proxy_upstream_server_healthy Upstream health state (1 healthy, 0 unhealthy).\n"
                "# TYPE dns_encrypted_proxy_upstream_server_healthy gauge\n"
                "# HELP dns_encrypted_proxy_upstream_server_consecutive_failures Consecutive failure count per upstream.\n"
                "# TYPE dns_encrypted_proxy_upstream_server_consecutive_failures gauge\n"
                "# HELP dns_encrypted_proxy_upstream_doh_forced_http_tier Active forced DoH protocol tier (0=h3,1=h2,2=h1).\n"
                "# TYPE dns_encrypted_proxy_upstream_doh_forced_http_tier gauge\n"
                "# HELP dns_encrypted_proxy_upstream_doh_upgrade_retry_remaining_milliseconds Remaining wait before next DoH protocol upgrade probe for upstream.\n"
                "# TYPE dns_encrypted_proxy_upstream_doh_upgrade_retry_remaining_milliseconds gauge\n"
                "# HELP dns_encrypted_proxy_upstream_doh_h3_consecutive_failures Consecutive h3 attempt failures for upstream; pin to h2 engages at threshold.\n"
                "# TYPE dns_encrypted_proxy_upstream_doh_h3_consecutive_failures gauge\n"
                "# HELP dns_encrypted_proxy_upstream_doh_attempt_failures_total Per-attempt DoH failures broken down by protocol tier and failure class.\n"
                "# TYPE dns_encrypted_proxy_upstream_doh_attempt_failures_total counter\n") != 0) {
        return -1;
    }

    if (g_upstream == NULL) {
        return 0;
    }

    /* Emit one series per configured upstream; cardinality is config-bounded. */
    for (int i = 0; i < g_upstream->server_count; i++) {
        const upstream_server_t *server = &g_upstream->servers[i];
        char escaped_url[2048];
        escape_label_value(server->url, escaped_url, sizeof(escaped_url));

        if (appendf(out,
                    out_size,
                    offset,
                    "dns_encrypted_proxy_upstream_server_requests_total{upstream=\"%s\",protocol=\"%s\"} %llu\n"
                    "dns_encrypted_proxy_upstream_server_failures_total{upstream=\"%s\",protocol=\"%s\"} %llu\n"
                    "dns_encrypted_proxy_upstream_server_healthy{upstream=\"%s\",protocol=\"%s\"} %d\n"
                "dns_encrypted_proxy_upstream_server_consecutive_failures{upstream=\"%s\",protocol=\"%s\"} %u\n",
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

        if (server->type == UPSTREAM_TYPE_DOH) {
            uint64_t now = now_monotonic_ms();
            uint64_t retry_remaining_ms = 0;
            if (server->stage.doh_upgrade_retry_after_ms > now) {
                retry_remaining_ms = server->stage.doh_upgrade_retry_after_ms - now;
            }
            if (appendf(
                    out,
                    out_size,
                    offset,
                    "dns_encrypted_proxy_upstream_doh_forced_http_tier{upstream=\"%s\",protocol=\"%s\"} %u\n"
                    "dns_encrypted_proxy_upstream_doh_upgrade_retry_remaining_milliseconds{upstream=\"%s\",protocol=\"%s\"} %llu\n"
                    "dns_encrypted_proxy_upstream_doh_h3_consecutive_failures{upstream=\"%s\",protocol=\"%s\"} %u\n",
                    escaped_url,
                    upstream_protocol_label(server->type),
                    (unsigned)server->stage.doh_forced_http_tier,
                    escaped_url,
                    upstream_protocol_label(server->type),
                    (unsigned long long)retry_remaining_ms,
                    escaped_url,
                    upstream_protocol_label(server->type),
                    (unsigned)server->stage.doh_h3_consecutive_failures)
                != 0) {
                return -1;
            }

            static const char *const tier_labels[DOH_HTTP_TIER_COUNT] = {"h3", "h2", "h1"};
            static const char *const class_labels[UPSTREAM_FAILURE_CLASS_COUNT] = {
                "unknown", "dns", "network", "transport", "timeout", "tls"};
            for (int t = 0; t < DOH_HTTP_TIER_COUNT; t++) {
                for (int c = 0; c < UPSTREAM_FAILURE_CLASS_COUNT; c++) {
                    uint64_t v = __atomic_load_n(&server->stage.doh_attempt_failures_total[t][c], __ATOMIC_RELAXED);
                    if (appendf(
                            out,
                            out_size,
                            offset,
                            "dns_encrypted_proxy_upstream_doh_attempt_failures_total{upstream=\"%s\",protocol=\"%s\",tier=\"%s\",class=\"%s\"} %llu\n",
                            escaped_url,
                            upstream_protocol_label(server->type),
                            tier_labels[t],
                            class_labels[c],
                            (unsigned long long)v)
                        != 0) {
                        return -1;
                    }
                }
            }
        }
    }

    if (g_facilitator != NULL) {
        upstream_facilitator_stats_t fs;
        if (upstream_facilitator_get_stats(g_facilitator, &fs) == 0) {
            if (appendf(
                    out,
                    out_size,
                    offset,
                    "# HELP dns_encrypted_proxy_upstream_dispatch_queue_depth Dispatch queue depth by queue type.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_queue_depth gauge\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_depth{queue=\"submit\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_depth{queue=\"work\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_depth{queue=\"completed\"} %llu\n"
                    "# HELP dns_encrypted_proxy_upstream_dispatch_members Members by state.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_members gauge\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"connecting\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"ready\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"enqueued\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"busy\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"cooldown\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"failed\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_members{state=\"draining\"} %llu\n"
                    "# HELP dns_encrypted_proxy_upstream_dispatch_events_total Dispatch events counters.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_events_total counter\n"
                    "dns_encrypted_proxy_upstream_dispatch_events_total{event=\"budget_exhausted\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_events_total{event=\"requeued\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_events_total{event=\"dropped\"} %llu\n"
                    "# HELP dns_encrypted_proxy_upstream_dispatch_queue_wait_milliseconds_avg Average queue wait before worker execution.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_queue_wait_milliseconds_avg gauge\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_milliseconds_avg %f\n"
                    "# HELP dns_encrypted_proxy_upstream_dispatch_queue_wait_milliseconds_max Maximum queue wait before worker execution.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_queue_wait_milliseconds_max gauge\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_milliseconds_max %llu\n"
                    "# HELP dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket Queue wait histogram buckets.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket counter\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"1\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"5\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"10\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"25\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"50\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"100\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"250\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"500\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"1000\"} %llu\n"
                    "dns_encrypted_proxy_upstream_dispatch_queue_wait_bucket{le=\"+Inf\"} %llu\n",
                    (unsigned long long)fs.submit_queue_depth,
                    (unsigned long long)fs.work_queue_depth,
                    (unsigned long long)fs.completed_queue_depth,
                    (unsigned long long)fs.members_connecting,
                    (unsigned long long)fs.members_ready,
                    (unsigned long long)fs.members_enqueued,
                    (unsigned long long)fs.members_busy,
                    (unsigned long long)fs.members_cooldown,
                    (unsigned long long)fs.members_failed,
                    (unsigned long long)fs.members_draining,
                    (unsigned long long)fs.budget_exhausted_total,
                    (unsigned long long)fs.requeued_total,
                    (unsigned long long)fs.dropped_total,
                    fs.queue_wait_samples_total == 0 ? 0.0 : (double)fs.queue_wait_ms_total / (double)fs.queue_wait_samples_total,
                    (unsigned long long)fs.queue_wait_ms_max,
                    (unsigned long long)fs.queue_wait_le_1ms,
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms + fs.queue_wait_le_25ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms + fs.queue_wait_le_25ms + fs.queue_wait_le_50ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms + fs.queue_wait_le_25ms + fs.queue_wait_le_50ms + fs.queue_wait_le_100ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms + fs.queue_wait_le_25ms + fs.queue_wait_le_50ms + fs.queue_wait_le_100ms + fs.queue_wait_le_250ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms + fs.queue_wait_le_25ms + fs.queue_wait_le_50ms + fs.queue_wait_le_100ms + fs.queue_wait_le_250ms + fs.queue_wait_le_500ms),
                    (unsigned long long)(fs.queue_wait_le_1ms + fs.queue_wait_le_5ms + fs.queue_wait_le_10ms + fs.queue_wait_le_25ms + fs.queue_wait_le_50ms + fs.queue_wait_le_100ms + fs.queue_wait_le_250ms + fs.queue_wait_le_500ms + fs.queue_wait_le_1000ms),
                    (unsigned long long)(fs.queue_wait_samples_total))
                != 0) {
                return -1;
            }
        }

        if (g_upstream != NULL) {
            if (appendf(
                    out,
                    out_size,
                    offset,
                    "# HELP dns_encrypted_proxy_upstream_dispatch_inflight Inflight dispatch jobs by upstream provider.\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_inflight gauge\n"
                    "# HELP dns_encrypted_proxy_upstream_dispatch_penalty Provider penalty score (higher means more de-prioritized).\n"
                    "# TYPE dns_encrypted_proxy_upstream_dispatch_penalty gauge\n")
                != 0) {
                return -1;
            }
            for (int i = 0; i < g_upstream->server_count; i++) {
                const upstream_server_t *server = &g_upstream->servers[i];
                char escaped_url[2048];
                escape_label_value(server->url, escaped_url, sizeof(escaped_url));
                uint64_t inflight = upstream_facilitator_get_provider_inflight(g_facilitator, i);
                if (appendf(
                        out,
                        out_size,
                        offset,
                        "dns_encrypted_proxy_upstream_dispatch_inflight{provider=\"%d\",upstream=\"%s\",protocol=\"%s\"} %llu\n",
                        i,
                        escaped_url,
                        upstream_protocol_label(server->type),
                        (unsigned long long)inflight)
                    != 0) {
                    return -1;
                }
                uint64_t penalty = upstream_facilitator_get_provider_penalty(g_facilitator, i);
                if (appendf(
                        out,
                        out_size,
                        offset,
                        "dns_encrypted_proxy_upstream_dispatch_penalty{provider=\"%d\",upstream=\"%s\",protocol=\"%s\"} %llu\n",
                        i,
                        escaped_url,
                        upstream_protocol_label(server->type),
                        (unsigned long long)penalty)
                    != 0) {
                    return -1;
                }
            }
        }
    }

    return 0;
}

static int append_pool_metric_row(
    char *out,
    size_t out_size,
    size_t *offset,
    const char *protocol,
    int capacity,
    int in_use,
    int idle,
    int connections_alive) {
    return appendf(
        out,
        out_size,
        offset,
        "dns_encrypted_proxy_upstream_pool_capacity{protocol=\"%s\"} %d\n"
        "dns_encrypted_proxy_upstream_pool_in_use{protocol=\"%s\"} %d\n"
        "dns_encrypted_proxy_upstream_pool_idle{protocol=\"%s\"} %d\n"
        "dns_encrypted_proxy_upstream_connections_alive{protocol=\"%s\"} %d\n",
        protocol,
        capacity,
        protocol,
        in_use,
        protocol,
        idle,
        protocol,
        connections_alive);
}

static int append_stage_fallback_metrics(
    char *out,
    size_t out_size,
    size_t *offset,
    const upstream_runtime_stats_t *runtime_stats) {
    if (runtime_stats == NULL) {
        return -1;
    }

    return appendf(
        out,
        out_size,
        offset,
        "# HELP dns_encrypted_proxy_upstream_stage_fallback_total Stage fallback outcomes by stage and result.\n"
        "# TYPE dns_encrypted_proxy_upstream_stage_fallback_total counter\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage2\",result=\"attempt\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage2\",result=\"success\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage2\",result=\"failure\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage2\",result=\"cooldown\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage3\",result=\"attempt\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage3\",result=\"success\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage3\",result=\"failure\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_fallback_total{stage=\"stage3\",result=\"cooldown\"} %llu\n"
        "# HELP dns_encrypted_proxy_upstream_stage_reason_total Stage fallback failures grouped by normalized reason class.\n"
        "# TYPE dns_encrypted_proxy_upstream_stage_reason_total counter\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage2\",reason=\"network\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage2\",reason=\"dns\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage2\",reason=\"transport\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage2\",reason=\"cooldown\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage2\",reason=\"other\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage3\",reason=\"network\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage3\",reason=\"dns\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage3\",reason=\"transport\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage3\",reason=\"cooldown\"} %llu\n"
        "dns_encrypted_proxy_upstream_stage_reason_total{stage=\"stage3\",reason=\"other\"} %llu\n",
        (unsigned long long)runtime_stats->stage2_attempts,
        (unsigned long long)runtime_stats->stage2_successes,
        (unsigned long long)runtime_stats->stage2_failures,
        (unsigned long long)runtime_stats->stage2_cooldowns,
        (unsigned long long)runtime_stats->stage3_attempts,
        (unsigned long long)runtime_stats->stage3_successes,
        (unsigned long long)runtime_stats->stage3_failures,
        (unsigned long long)runtime_stats->stage3_cooldowns,
        (unsigned long long)runtime_stats->stage2_reason_network,
        (unsigned long long)runtime_stats->stage2_reason_dns,
        (unsigned long long)runtime_stats->stage2_reason_transport,
        (unsigned long long)runtime_stats->stage2_reason_cooldown,
        (unsigned long long)runtime_stats->stage2_reason_other,
        (unsigned long long)runtime_stats->stage3_reason_network,
        (unsigned long long)runtime_stats->stage3_reason_dns,
        (unsigned long long)runtime_stats->stage3_reason_transport,
        (unsigned long long)runtime_stats->stage3_reason_cooldown,
        (unsigned long long)runtime_stats->stage3_reason_other);
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

    double process_cpu_percent = 0.0;
    double process_cpu_seconds = 0.0;
    if (read_process_cpu_seconds(&process_cpu_seconds) == 0) {
        if (g_prev_process_cpu_wall_ms > 0 && now_ms > g_prev_process_cpu_wall_ms && process_cpu_seconds >= g_prev_process_cpu_seconds) {
            double wall_seconds = (double)(now_ms - g_prev_process_cpu_wall_ms) / 1000.0;
            double cpu_delta = process_cpu_seconds - g_prev_process_cpu_seconds;
            if (wall_seconds > 0.0) {
                process_cpu_percent = (cpu_delta / wall_seconds) * 100.0;
                if (process_cpu_percent < 0.0) {
                    process_cpu_percent = 0.0;
                }
            }
        }
        g_prev_process_cpu_seconds = process_cpu_seconds;
        g_prev_process_cpu_wall_ms = now_ms;
    }

    uint64_t process_rss_bytes = 0;
    (void)read_process_rss_bytes(&process_rss_bytes);

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
    int doq_pool_idle = runtime_stats.doq_pool_capacity - runtime_stats.doq_pool_in_use;
    if (doh_pool_idle < 0) {
        doh_pool_idle = 0;
    }
    if (dot_pool_idle < 0) {
        dot_pool_idle = 0;
    }
    if (doq_pool_idle < 0) {
        doq_pool_idle = 0;
    }

    size_t offset = 0;
    if (appendf(
            out,
            out_size,
            &offset,
            "# ---- traffic and responses ----\n"
            "# HELP dns_encrypted_proxy_uptime_seconds Process uptime in seconds.\n"
            "# TYPE dns_encrypted_proxy_uptime_seconds gauge\n"
            "dns_encrypted_proxy_uptime_seconds %.3f\n"
            "# HELP dns_encrypted_proxy_process_cpu_percent Process CPU usage percentage over last metrics scrape interval.\n"
            "# TYPE dns_encrypted_proxy_process_cpu_percent gauge\n"
            "dns_encrypted_proxy_process_cpu_percent %.3f\n"
            "# HELP dns_encrypted_proxy_process_memory_rss_bytes Process resident memory usage in bytes.\n"
            "# TYPE dns_encrypted_proxy_process_memory_rss_bytes gauge\n"
            "dns_encrypted_proxy_process_memory_rss_bytes %llu\n"
            "# HELP dns_encrypted_proxy_queries_udp_total Total number of DNS queries received over UDP.\n"
            "# TYPE dns_encrypted_proxy_queries_udp_total counter\n"
            "dns_encrypted_proxy_queries_udp_total %llu\n"
            "# HELP dns_encrypted_proxy_queries_tcp_total Total number of DNS queries received over TCP.\n"
            "# TYPE dns_encrypted_proxy_queries_tcp_total counter\n"
            "dns_encrypted_proxy_queries_tcp_total %llu\n"
            "# HELP dns_encrypted_proxy_cache_hits_total Total number of cache hits.\n"
            "# TYPE dns_encrypted_proxy_cache_hits_total counter\n"
            "dns_encrypted_proxy_cache_hits_total %llu\n"
            "# HELP dns_encrypted_proxy_cache_misses_total Total number of cache misses.\n"
            "# TYPE dns_encrypted_proxy_cache_misses_total counter\n"
            "dns_encrypted_proxy_cache_misses_total %llu\n"
            "# HELP dns_encrypted_proxy_upstream_success_total Total number of successful upstream resolutions.\n"
            "# TYPE dns_encrypted_proxy_upstream_success_total counter\n"
            "dns_encrypted_proxy_upstream_success_total %llu\n"
            "# HELP dns_encrypted_proxy_upstream_failures_total Total number of failed upstream resolutions.\n"
            "# TYPE dns_encrypted_proxy_upstream_failures_total counter\n"
            "dns_encrypted_proxy_upstream_failures_total %llu\n"
            "# HELP dns_encrypted_proxy_servfail_sent_total Total number of SERVFAIL responses sent by the proxy.\n"
            "# TYPE dns_encrypted_proxy_servfail_sent_total counter\n"
            "dns_encrypted_proxy_servfail_sent_total %llu\n"
            "# HELP dns_encrypted_proxy_internal_errors_total Total number of internal proxy errors detected while processing requests.\n"
            "# TYPE dns_encrypted_proxy_internal_errors_total counter\n"
            "dns_encrypted_proxy_internal_errors_total %llu\n"
            "# HELP dns_encrypted_proxy_truncated_sent_total Total number of truncated UDP responses sent.\n"
            "# TYPE dns_encrypted_proxy_truncated_sent_total counter\n"
            "dns_encrypted_proxy_truncated_sent_total %llu\n"
            "# HELP dns_encrypted_proxy_tcp_connections_total Total number of accepted TCP client connections.\n"
            "# TYPE dns_encrypted_proxy_tcp_connections_total counter\n"
            "dns_encrypted_proxy_tcp_connections_total %llu\n"
            "# HELP dns_encrypted_proxy_tcp_connections_rejected_total Total number of rejected TCP client connections.\n"
            "# TYPE dns_encrypted_proxy_tcp_connections_rejected_total counter\n"
            "dns_encrypted_proxy_tcp_connections_rejected_total %llu\n"
            "# HELP dns_encrypted_proxy_tcp_connections_active Number of currently active TCP client connections.\n"
            "# TYPE dns_encrypted_proxy_tcp_connections_active gauge\n"
            "dns_encrypted_proxy_tcp_connections_active %d\n"
            "# HELP dns_encrypted_proxy_responses_total Total number of DNS responses sent by the proxy.\n"
            "# TYPE dns_encrypted_proxy_responses_total counter\n"
            "dns_encrypted_proxy_responses_total %llu\n"
            "# HELP dns_encrypted_proxy_responses_rcode_total Total number of DNS responses by RCODE.\n"
            "# TYPE dns_encrypted_proxy_responses_rcode_total counter\n"
            "dns_encrypted_proxy_responses_rcode_total{rcode=\"NOERROR\"} %llu\n"
            "dns_encrypted_proxy_responses_rcode_total{rcode=\"SERVFAIL\"} %llu\n"
            "dns_encrypted_proxy_responses_rcode_total{rcode=\"NXDOMAIN\"} %llu\n"
            "dns_encrypted_proxy_responses_rcode_total{rcode=\"REFUSED\"} %llu\n"
            "dns_encrypted_proxy_responses_rcode_total{rcode=\"OTHER\"} %llu\n",
            uptime_seconds,
            process_cpu_percent,
            (unsigned long long)process_rss_bytes,
            (unsigned long long)atomic_load(&m->queries_udp),
            (unsigned long long)atomic_load(&m->queries_tcp),
            (unsigned long long)atomic_load(&m->cache_hits),
            (unsigned long long)atomic_load(&m->cache_misses),
            (unsigned long long)atomic_load(&m->upstream_success),
            (unsigned long long)atomic_load(&m->upstream_failures),
            (unsigned long long)atomic_load(&m->servfail_sent),
            (unsigned long long)atomic_load(&m->internal_errors_total),
            (unsigned long long)atomic_load(&m->truncated_sent),
            (unsigned long long)atomic_load(&m->tcp_connections_total),
            (unsigned long long)atomic_load(&m->tcp_connections_rejected),
            (int)atomic_load(&m->tcp_connections_active),
            (unsigned long long)atomic_load(&m->responses_total),
            (unsigned long long)atomic_load(&m->responses_rcode[0]),
            (unsigned long long)atomic_load(&m->responses_rcode[2]),
            (unsigned long long)atomic_load(&m->responses_rcode[3]),
            (unsigned long long)atomic_load(&m->responses_rcode[5]),
            (unsigned long long)rcode_other) != 0) {
        return -1;
    }

    if (appendf(
            out,
            out_size,
            &offset,
            "\n"
            "# ---- cache and metrics endpoint ----\n"
            "# HELP dns_encrypted_proxy_cache_entries Number of cache entries currently in use.\n"
            "# TYPE dns_encrypted_proxy_cache_entries gauge\n"
            "dns_encrypted_proxy_cache_entries %llu\n"
            "# HELP dns_encrypted_proxy_cache_capacity Total configured cache entry capacity.\n"
            "# TYPE dns_encrypted_proxy_cache_capacity gauge\n"
            "dns_encrypted_proxy_cache_capacity %llu\n"
            "# HELP dns_encrypted_proxy_cache_evictions_total Total cache evictions due to capacity pressure.\n"
            "# TYPE dns_encrypted_proxy_cache_evictions_total counter\n"
            "dns_encrypted_proxy_cache_evictions_total %llu\n"
            "# HELP dns_encrypted_proxy_cache_expirations_total Total cache entries expired and removed.\n"
            "# TYPE dns_encrypted_proxy_cache_expirations_total counter\n"
            "dns_encrypted_proxy_cache_expirations_total %llu\n"
            "# HELP dns_encrypted_proxy_cache_bytes_in_use Approximate bytes currently held by cache key/value payloads.\n"
            "# TYPE dns_encrypted_proxy_cache_bytes_in_use gauge\n"
            "dns_encrypted_proxy_cache_bytes_in_use %llu\n"
            "# HELP dns_encrypted_proxy_metrics_http_requests_total Total HTTP requests received by the metrics endpoint.\n"
            "# TYPE dns_encrypted_proxy_metrics_http_requests_total counter\n"
            "dns_encrypted_proxy_metrics_http_requests_total %llu\n"
            "# HELP dns_encrypted_proxy_metrics_http_responses_total Total HTTP responses returned by status code class.\n"
            "# TYPE dns_encrypted_proxy_metrics_http_responses_total counter\n"
            "dns_encrypted_proxy_metrics_http_responses_total{code_class=\"2xx\"} %llu\n"
            "dns_encrypted_proxy_metrics_http_responses_total{code_class=\"4xx\"} %llu\n"
            "dns_encrypted_proxy_metrics_http_responses_total{code_class=\"5xx\"} %llu\n"
            "# HELP dns_encrypted_proxy_metrics_http_in_flight Number of in-flight HTTP metrics requests.\n"
            "# TYPE dns_encrypted_proxy_metrics_http_in_flight gauge\n"
            "dns_encrypted_proxy_metrics_http_in_flight %d\n",
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
            "\n"
            "# ---- upstream pools and protocol runtime ----\n"
            "# HELP dns_encrypted_proxy_upstream_pool_capacity Configured upstream connection/handle pool capacity by protocol.\n"
            "# TYPE dns_encrypted_proxy_upstream_pool_capacity gauge\n"
            "# HELP dns_encrypted_proxy_upstream_pool_in_use Number of upstream connection/handle slots currently in use by protocol.\n"
            "# TYPE dns_encrypted_proxy_upstream_pool_in_use gauge\n"
            "# HELP dns_encrypted_proxy_upstream_pool_idle Number of idle upstream connection/handle slots by protocol.\n"
            "# TYPE dns_encrypted_proxy_upstream_pool_idle gauge\n"
            "# HELP dns_encrypted_proxy_upstream_connections_alive Number of currently established upstream transport connections by protocol.\n"
            "# TYPE dns_encrypted_proxy_upstream_connections_alive gauge\n"
            "# HELP dns_encrypted_proxy_doh_http_responses_total Total DoH responses by negotiated HTTP version.\n"
            "# TYPE dns_encrypted_proxy_doh_http_responses_total counter\n"
            "dns_encrypted_proxy_doh_http_responses_total{version=\"h3\"} %llu\n"
            "dns_encrypted_proxy_doh_http_responses_total{version=\"h2\"} %llu\n"
            "dns_encrypted_proxy_doh_http_responses_total{version=\"h1\"} %llu\n"
            "dns_encrypted_proxy_doh_http_responses_total{version=\"other\"} %llu\n"
            "# HELP dns_encrypted_proxy_doh_protocol_downgrades_total Total DoH protocol downgrade outcomes.\n"
            "# TYPE dns_encrypted_proxy_doh_protocol_downgrades_total counter\n"
            "dns_encrypted_proxy_doh_protocol_downgrades_total{from=\"h3\",to=\"h2\"} %llu\n"
            "dns_encrypted_proxy_doh_protocol_downgrades_total{from=\"h3\",to=\"h1\"} %llu\n"
            "dns_encrypted_proxy_doh_protocol_downgrades_total{from=\"h2\",to=\"h1\"} %llu\n"
            "# HELP dns_encrypted_proxy_doh_protocol_upgrade_probes_total Total DoH protocol upgrade probe outcomes.\n"
            "# TYPE dns_encrypted_proxy_doh_protocol_upgrade_probes_total counter\n"
            "dns_encrypted_proxy_doh_protocol_upgrade_probes_total{result=\"attempt\"} %llu\n"
            "dns_encrypted_proxy_doh_protocol_upgrade_probes_total{result=\"success\"} %llu\n"
            "dns_encrypted_proxy_doh_protocol_upgrade_probes_total{result=\"failure\"} %llu\n"
            "# HELP dns_encrypted_proxy_upstream_stage1_cache_total Upstream stage1 resolver cache counters.\n"
            "# TYPE dns_encrypted_proxy_upstream_stage1_cache_total counter\n"
            "dns_encrypted_proxy_upstream_stage1_cache_total{result=\"hit\"} %llu\n"
            "dns_encrypted_proxy_upstream_stage1_cache_total{result=\"miss\"} %llu\n"
            "dns_encrypted_proxy_upstream_stage1_cache_total{result=\"refresh\"} %llu\n"
            "dns_encrypted_proxy_upstream_stage1_cache_total{result=\"invalidate\"} %llu\n",
            (unsigned long long)runtime_stats.doh_http3_responses_total,
            (unsigned long long)runtime_stats.doh_http2_responses_total,
            (unsigned long long)runtime_stats.doh_http1_responses_total,
            (unsigned long long)runtime_stats.doh_http_other_responses_total,
            (unsigned long long)runtime_stats.doh_downgrade_h3_to_h2_total,
            (unsigned long long)runtime_stats.doh_downgrade_h3_to_h1_total,
            (unsigned long long)runtime_stats.doh_downgrade_h2_to_h1_total,
            (unsigned long long)runtime_stats.doh_upgrade_probe_attempt_total,
            (unsigned long long)runtime_stats.doh_upgrade_probe_success_total,
            (unsigned long long)runtime_stats.doh_upgrade_probe_failure_total,
            (unsigned long long)runtime_stats.stage1_cache_hits,
            (unsigned long long)runtime_stats.stage1_cache_misses,
            (unsigned long long)runtime_stats.stage1_cache_refreshes,
            (unsigned long long)runtime_stats.stage1_cache_invalidations) != 0) {
        return -1;
    }

    if (append_stage_fallback_metrics(out, out_size, &offset, &runtime_stats) != 0) {
        return -1;
    }

    if (append_pool_metric_row(
            out,
            out_size,
            &offset,
            "doh",
            runtime_stats.doh_pool_capacity,
            runtime_stats.doh_pool_in_use,
            doh_pool_idle,
            0)
        != 0) {
        return -1;
    }

    if (append_pool_metric_row(
            out,
            out_size,
            &offset,
            "dot",
            runtime_stats.dot_pool_capacity,
            runtime_stats.dot_pool_in_use,
            dot_pool_idle,
            runtime_stats.dot_connections_alive)
        != 0) {
        return -1;
    }

    if (append_pool_metric_row(
            out,
            out_size,
            &offset,
            "doq",
            runtime_stats.doq_pool_capacity,
            runtime_stats.doq_pool_in_use,
            doq_pool_idle,
            runtime_stats.doq_connections_alive)
        != 0) {
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
    const int is_healthz = (strncmp(req, "GET /healthz ", 13) == 0);
    const int is_readyz = (strncmp(req, "GET /readyz ", 12) == 0);

    if (is_healthz) {
        const char *body = "ok\n";
        char header[192];
        int header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n",
            strlen(body));
        if (header_len > 0 && (size_t)header_len < sizeof(header) &&
            write_all(client_fd, header, (size_t)header_len) == 0 &&
            write_all(client_fd, body, strlen(body)) == 0) {
            if (g_metrics != NULL) {
                atomic_fetch_add(&g_metrics->metrics_http_responses_2xx_total, 1);
            }
        } else if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
    }

    if (is_readyz) {
        int ready = 0;
        if (g_facilitator != NULL) {
            upstream_facilitator_stats_t fs;
            if (upstream_facilitator_get_stats(g_facilitator, &fs) == 0 && fs.members_ready > 0) {
                ready = 1;
            }
        } else {
            ready = (g_upstream != NULL && upstream_is_ready(g_upstream));
        }
        const char *body = ready ? "ready\n" : "not ready\n";
        int status = ready ? 200 : 503;
        char header[192];
        int header_len = snprintf(
            header,
            sizeof(header),
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n",
            status,
            ready ? "OK" : "Service Unavailable",
            strlen(body));
        if (header_len > 0 && (size_t)header_len < sizeof(header) &&
            write_all(client_fd, header, (size_t)header_len) == 0 &&
            write_all(client_fd, body, strlen(body)) == 0) {
            if (g_metrics != NULL) {
                if (ready) {
                    atomic_fetch_add(&g_metrics->metrics_http_responses_2xx_total, 1);
                } else {
                    atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
                }
            }
        } else if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
    }

    if (!is_metrics) {
        const char *resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)write_all(client_fd, resp, strlen(resp));
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_4xx_total, 1);
        }
        goto done;
    }

    char *body = (char *)malloc(32768);
    if (body == NULL) {
        const char *resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        (void)write_all(client_fd, resp, strlen(resp));
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
    }

    int body_len = build_metrics_body(g_metrics, body, 32768);
    if (body_len < 0) {
        free(body);
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
        free(body);
        if (g_metrics != NULL) {
            atomic_fetch_add(&g_metrics->metrics_http_responses_5xx_total, 1);
        }
        goto done;
    }

    if (write_all(client_fd, header, (size_t)header_len) != 0) {
        free(body);
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
    free(body);

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
    atomic_store(&m->internal_errors_total, 0);
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

proxy_status_t metrics_server_start(
    proxy_metrics_t *m,
    dns_cache_t *cache,
    upstream_client_t *upstream,
    upstream_facilitator_t *facilitator,
    int port) {
    if (m == NULL || port <= 0 || port > 65535) {
        return set_error(PROXY_ERR_INVALID_ARG,
                         "m=%p port=%d (expected 1..65535)",
                         (const void *)m, port);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return set_error_errno(PROXY_ERR_NETWORK,
                               "socket(AF_INET, SOCK_STREAM)");
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
        return set_error_errno(PROXY_ERR_NETWORK,
                               "bind metrics socket on 0.0.0.0:%d",
                               port);
    }
    if (listen(fd, 32) != 0) {
        close(fd);
        return set_error_errno(PROXY_ERR_NETWORK,
                               "listen on metrics port %d",
                               port);
    }

    g_metrics = m;
    g_cache = cache;
    g_upstream = upstream;
    g_facilitator = facilitator;
    g_start_monotonic_ms = now_monotonic_ms();
    g_prev_process_cpu_wall_ms = 0;
    g_prev_process_cpu_seconds = 0.0;
    g_listen_fd = fd;
    atomic_store(&g_stop, 0);

    int thread_rc = pthread_create(&g_thread, NULL, metrics_thread_main, NULL);
    if (thread_rc != 0) {
        close(fd);
        g_listen_fd = -1;
        g_metrics = NULL;
        g_cache = NULL;
        g_upstream = NULL;
        g_facilitator = NULL;
        g_start_monotonic_ms = 0;
        return set_error(PROXY_ERR_RESOURCE,
                         "pthread_create metrics thread failed (rc=%d)",
                         thread_rc);
    }

    g_thread_started = 1;
    return PROXY_OK;
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
    g_facilitator = NULL;
    g_start_monotonic_ms = 0;
    g_prev_process_cpu_wall_ms = 0;
    g_prev_process_cpu_seconds = 0.0;
}
