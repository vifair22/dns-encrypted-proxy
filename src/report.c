#define _POSIX_C_SOURCE 200809L

#include "report.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* The address is written once, before the descriptor is published with
 * release order, so a sender that sees the descriptor also sees the address. */
static struct sockaddr_un g_report_addr;
static socklen_t g_report_addr_len;
static atomic_int g_report_fd = -1;
static atomic_uint_fast64_t g_report_sent;
static atomic_uint_fast64_t g_report_dropped;

static _Thread_local char t_failure_reason[48];
static _Thread_local char t_failure_detail[96];

proxy_status_t report_open(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return set_error(PROXY_ERR_INVALID_ARG, "report socket path is empty");
    }
    size_t len = strlen(path);
    if (len >= sizeof(g_report_addr.sun_path)) {
        return set_error(PROXY_ERR_CONFIG, "report_socket path is longer than %zu bytes: %s",
                         sizeof(g_report_addr.sun_path) - 1, path);
    }
    if (atomic_load(&g_report_fd) >= 0) {
        return set_error(PROXY_ERR_INTERNAL, "report socket is already open");
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return set_error_errno(PROXY_ERR_NETWORK, "socket(AF_UNIX, SOCK_DGRAM) for report_socket");
    }

    memset(&g_report_addr, 0, sizeof(g_report_addr));
    g_report_addr.sun_family = AF_UNIX;
    memcpy(g_report_addr.sun_path, path, len + 1);
    g_report_addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len + 1);

    atomic_store_explicit(&g_report_fd, fd, memory_order_release);
    return PROXY_OK;
}

void report_close(void) {
    int fd = atomic_exchange(&g_report_fd, -1);
    if (fd >= 0) {
        close(fd);
    }
}

int report_enabled(void) {
    return atomic_load_explicit(&g_report_fd, memory_order_acquire) >= 0;
}

void report_note_attempt_failure(const char *reason, const char *detail) {
    (void)snprintf(t_failure_reason, sizeof(t_failure_reason), "%s", reason != NULL ? reason : "");
    (void)snprintf(t_failure_detail, sizeof(t_failure_detail), "%s", detail != NULL ? detail : "");
}

void report_take_attempt_failure(char *reason, size_t reason_len, char *detail, size_t detail_len) {
    if (reason != NULL && reason_len > 0) {
        (void)snprintf(reason, reason_len, "%s", t_failure_reason);
    }
    if (detail != NULL && detail_len > 0) {
        (void)snprintf(detail, detail_len, "%s", t_failure_detail);
    }
    t_failure_reason[0] = '\0';
    t_failure_detail[0] = '\0';
}

uint64_t report_sent_total(void) {
    return (uint64_t)atomic_load(&g_report_sent);
}

uint64_t report_dropped_total(void) {
    return (uint64_t)atomic_load(&g_report_dropped);
}

static double report_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0.0;
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Unconnected sendto on every event, so a collector that restarts and
 * recreates its socket is picked up by the next event with no reconnect
 * logic here. */
static void report_send(const char *buf, int len) {
    int fd = atomic_load_explicit(&g_report_fd, memory_order_acquire);
    if (fd < 0) {
        return;
    }
    if (len < 0) {
        atomic_fetch_add(&g_report_dropped, 1);
        return;
    }
    ssize_t sent = sendto(fd, buf, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL,
                          (const struct sockaddr *)&g_report_addr, g_report_addr_len);
    if (sent == (ssize_t)len) {
        atomic_fetch_add(&g_report_sent, 1);
    } else {
        atomic_fetch_add(&g_report_dropped, 1);
    }
}

/* ------------------------------------------------------------------------ */
/* JSON encoding                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int overflow;
} json_out_t;

static void out_raw(json_out_t *out, const char *s, size_t n) {
    if (out->overflow || n > out->cap - out->len) {
        out->overflow = 1;
        return;
    }
    memcpy(out->buf + out->len, s, n);
    out->len += n;
}

static void out_str(json_out_t *out, const char *s) {
    out_raw(out, s, strlen(s));
}

__attribute__((format(printf, 2, 3)))
static void out_fmt(json_out_t *out, const char *fmt, ...) {
    if (out->overflow) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out->buf + out->len, out->cap - out->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= out->cap - out->len) {
        out->overflow = 1;
        return;
    }
    out->len += (size_t)n;
}

/* Names are raw label bytes, so anything outside printable ASCII is escaped
 * as \u00XX. That keeps every datagram valid UTF-8 JSON whatever a client
 * puts in a query. */
static void out_json_string(json_out_t *out, const char *s) {
    if (s == NULL) {
        out_str(out, "null");
        return;
    }
    out_raw(out, "\"", 1);
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        unsigned char c = *p;
        if (c == '"') {
            out_raw(out, "\\\"", 2);
        } else if (c == '\\') {
            out_raw(out, "\\\\", 2);
        } else if (c < 0x20 || c >= 0x7f) {
            out_fmt(out, "\\u%04x", (unsigned int)c);
        } else {
            out_raw(out, (const char *)p, 1);
        }
    }
    out_raw(out, "\"", 1);
}

static void out_key(json_out_t *out, const char *key) {
    out_raw(out, ",\"", 2);
    out_str(out, key);
    out_raw(out, "\":", 2);
}

static int out_finish(json_out_t *out) {
    out_raw(out, "}", 1);
    if (out->overflow || out->len >= out->cap) {
        return -1;
    }
    out->buf[out->len] = '\0';
    return (int)out->len;
}

const char *report_qtype_name(uint16_t qtype, char *scratch, size_t scratch_len) {
    switch (qtype) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 35: return "NAPTR";
        case 43: return "DS";
        case 46: return "RRSIG";
        case 47: return "NSEC";
        case 48: return "DNSKEY";
        case 50: return "NSEC3";
        case 52: return "TLSA";
        case 64: return "SVCB";
        case 65: return "HTTPS";
        case 252: return "AXFR";
        case 255: return "ANY";
        case 257: return "CAA";
        default: break;
    }
    /* RFC 3597 generic form for everything else. */
    (void)snprintf(scratch, scratch_len, "TYPE%u", (unsigned int)qtype);
    return scratch;
}

const char *report_rcode_name(uint8_t rcode, char *scratch, size_t scratch_len) {
    static const char *const names[] = {
        "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
        "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE",
    };
    if (rcode < sizeof(names) / sizeof(names[0])) {
        return names[rcode];
    }
    (void)snprintf(scratch, scratch_len, "RCODE%u", (unsigned int)rcode);
    return scratch;
}

static const char *report_source_name(report_source_t source) {
    switch (source) {
        case REPORT_SOURCE_UPSTREAM: return "upstream";
        case REPORT_SOURCE_CACHE: return "cache";
        case REPORT_SOURCE_FAILURE_CACHE: return "failure_cache";
        case REPORT_SOURCE_LOCAL: return "local";
        default: return "unknown";
    }
}

int report_format_query(char *buf, size_t capacity, double ts, const report_query_t *query) {
    if (buf == NULL || capacity == 0 || query == NULL) {
        return -1;
    }
    json_out_t out = {.buf = buf, .cap = capacity, .len = 0, .overflow = 0};
    char qtype_scratch[16];
    char rcode_scratch[16];

    out_fmt(&out, "{\"type\":\"dns.query\",\"ts\":%.3f", ts);
    out_key(&out, "client");
    out_json_string(&out, query->client);
    out_key(&out, "qname");
    if (query->qname != NULL && query->qname[0] == '\0') {
        out_json_string(&out, ".");
    } else {
        out_json_string(&out, query->qname);
    }
    out_key(&out, "qtype");
    out_json_string(&out, query->has_qtype ? report_qtype_name(query->qtype, qtype_scratch, sizeof(qtype_scratch)) : NULL);
    out_key(&out, "rcode");
    out_json_string(&out, report_rcode_name(query->rcode, rcode_scratch, sizeof(rcode_scratch)));
    int from_upstream = query->source == REPORT_SOURCE_UPSTREAM;
    out_key(&out, "upstream");
    out_json_string(&out, from_upstream ? query->upstream : NULL);
    out_key(&out, "proto");
    out_json_string(&out, from_upstream ? query->proto : NULL);
    out_key(&out, "source");
    out_json_string(&out, report_source_name(query->source));
    out_key(&out, "latency_ms");
    out_fmt(&out, "%.3f", query->latency_ms);
    out_key(&out, "cached");
    out_str(&out, query->source == REPORT_SOURCE_CACHE || query->source == REPORT_SOURCE_FAILURE_CACHE ? "true" : "false");
    return out_finish(&out);
}

int report_format_upstream(
    char *buf,
    size_t capacity,
    double ts,
    const char *upstream,
    const char *event,
    const char *reason,
    const char *detail) {
    if (buf == NULL || capacity == 0 || event == NULL) {
        return -1;
    }
    json_out_t out = {.buf = buf, .cap = capacity, .len = 0, .overflow = 0};
    out_fmt(&out, "{\"type\":\"dns.upstream\",\"ts\":%.3f", ts);
    out_key(&out, "upstream");
    out_json_string(&out, upstream);
    out_key(&out, "event");
    out_json_string(&out, event);
    out_key(&out, "reason");
    out_json_string(&out, reason);
    out_key(&out, "detail");
    out_json_string(&out, detail);
    return out_finish(&out);
}

void report_query(const report_query_t *query) {
    if (!report_enabled() || query == NULL) {
        return;
    }
    char buf[REPORT_MAX_DATAGRAM];
    int len = report_format_query(buf, sizeof(buf), report_now(), query);
    report_send(buf, len);
}

void report_upstream(const char *upstream, const char *event, const char *reason, const char *detail) {
    if (!report_enabled() || event == NULL) {
        return;
    }
    char buf[REPORT_MAX_DATAGRAM];
    int len = report_format_upstream(buf, sizeof(buf), report_now(), upstream, event, reason, detail);
    report_send(buf, len);
}
