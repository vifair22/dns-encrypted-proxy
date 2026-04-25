#define _POSIX_C_SOURCE 200809L

#include "iterative_resolver.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#ifndef DNS_PORT
#define DNS_PORT 53
#endif
#define DNS_HEADER_SIZE 12
#define DNS_MAX_PACKET 1232
#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_CLASS_IN 1

#define ITER_MAX_DEPTH 6
#define ITER_MAX_HOPS 8
#define ITER_MAX_NS 12
#define ITER_CACHE_ENTRIES 64
#define ITER_CACHE_TTL_FALLBACK_MS 60000ULL
#define ITER_CACHE_TTL_MIN_MS 5000ULL
#define ITER_CACHE_TTL_MAX_MS 3600000ULL

static const char *k_root_servers[] = {
    "198.41.0.4",      /* a.root-servers.net */
    "199.9.14.201",    /* b.root-servers.net */
    "192.33.4.12",     /* c.root-servers.net */
    "199.7.91.13",     /* d.root-servers.net */
    "192.203.230.10",  /* e.root-servers.net */
    "192.5.5.241",     /* f.root-servers.net */
};

typedef struct {
    uint32_t ips[ITER_MAX_NS];
    int count;
} ip_list_t;

typedef struct {
    int got_a;
    uint32_t a_addr_be;
    uint32_t a_ttl;
    char cname_target[256];

    char ns_names[ITER_MAX_NS][256];
    int ns_name_count;

    uint32_t glue_ips[ITER_MAX_NS];
    int glue_count;
} parsed_response_t;

typedef struct {
    char host[256];
    uint32_t addr_v4_be;
    uint64_t expires_at_ms;
    int in_use;
} iterative_cache_entry_t;

static iterative_cache_entry_t g_cache[ITER_CACHE_ENTRIES];
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static int normalize_hostname(const char *in, char *out, size_t out_len) {
    if (in == NULL || out == NULL || out_len < 2) {
        return -1;
    }

    size_t n = strlen(in);
    while (n > 0 && isspace((unsigned char)in[n - 1])) {
        n--;
    }
    while (n > 0 && isspace((unsigned char)*in)) {
        in++;
        n--;
    }
    if (n == 0) {
        return -1;
    }
    if (in[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n >= out_len) {
        return -1;
    }

    memcpy(out, in, n);
    out[n] = '\0';
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)out[i];
        if (ch >= 'A' && ch <= 'Z') {
            out[i] = (char)(ch - 'A' + 'a');
        }
    }
    return 0;
}

static int encode_qname(const char *name, uint8_t *out, size_t out_len, size_t *written_out) {
    if (name == NULL || out == NULL || written_out == NULL) {
        return -1;
    }

    size_t off = 0;
    const char *label = name;
    while (*label != '\0') {
        const char *dot = strchr(label, '.');
        size_t len = dot ? (size_t)(dot - label) : strlen(label);
        if (len == 0 || len > 63 || off + 1 + len >= out_len) {
            return -1;
        }
        out[off++] = (uint8_t)len;
        memcpy(out + off, label, len);
        off += len;
        if (!dot) {
            break;
        }
        label = dot + 1;
    }

    if (off + 1 > out_len) {
        return -1;
    }
    out[off++] = 0;
    *written_out = off;
    return 0;
}

static int skip_name(const uint8_t *msg, size_t msg_len, size_t *off) {
    if (msg == NULL || off == NULL || *off >= msg_len) {
        return -1;
    }
    size_t pos = *off;
    int steps = 0;
    while (pos < msg_len) {
        if (++steps > 255) {
            return -1;
        }
        uint8_t len = msg[pos];
        if (len == 0) {
            *off = pos + 1;
            return 0;
        }
        if ((len & 0xC0u) == 0xC0u) {
            if (pos + 1 >= msg_len) {
                return -1;
            }
            *off = pos + 2;
            return 0;
        }
        if ((len & 0xC0u) != 0 || len > 63) {
            return -1;
        }
        pos += 1 + len;
    }
    return -1;
}

static int read_name(const uint8_t *msg, size_t msg_len, size_t *off, char *out, size_t out_len) {
    if (msg == NULL || off == NULL || out == NULL || out_len == 0 || *off >= msg_len) {
        return -1;
    }

    size_t pos = *off;
    size_t consumed = pos;
    size_t out_pos = 0;
    int jumped = 0;
    int steps = 0;

    while (pos < msg_len) {
        if (++steps > 255) {
            return -1;
        }

        uint8_t len = msg[pos];
        if (len == 0) {
            if (!jumped) {
                consumed = pos + 1;
            }
            if (out_pos == 0) {
                if (out_len < 2) {
                    return -1;
                }
                out[out_pos++] = '.';
            }
            if (out_pos >= out_len) {
                return -1;
            }
            out[out_pos] = '\0';
            *off = consumed;
            return 0;
        }

        if ((len & 0xC0u) == 0xC0u) {
            if (pos + 1 >= msg_len) {
                return -1;
            }
            uint16_t ptr = (uint16_t)(((len & 0x3Fu) << 8) | msg[pos + 1]);
            if ((size_t)ptr >= msg_len) {
                return -1;
            }
            if (!jumped) {
                consumed = pos + 2;
                jumped = 1;
            }
            pos = (size_t)ptr;
            continue;
        }

        if ((len & 0xC0u) != 0 || len > 63 || pos + 1 + len > msg_len) {
            return -1;
        }

        if (out_pos != 0) {
            if (out_pos + 1 >= out_len) {
                return -1;
            }
            out[out_pos++] = '.';
        }

        for (uint8_t i = 0; i < len; i++) {
            unsigned char ch = msg[pos + 1 + i];
            if (ch >= 'A' && ch <= 'Z') {
                ch = (unsigned char)(ch - 'A' + 'a');
            }
            if (out_pos + 1 >= out_len) {
                return -1;
            }
            out[out_pos++] = (char)ch;
        }

        pos += 1 + len;
        if (!jumped) {
            consumed = pos;
        }
    }
    return -1;
}

static int ip_list_add(ip_list_t *list, uint32_t ip_be) {
    if (list == NULL || list->count >= ITER_MAX_NS) {
        return -1;
    }
    for (int i = 0; i < list->count; i++) {
        if (list->ips[i] == ip_be) {
            return 0;
        }
    }
    list->ips[list->count++] = ip_be;
    return 0;
}

static int cache_lookup(const char *host, uint32_t *addr_v4_be_out) {
    if (host == NULL || addr_v4_be_out == NULL) {
        return 0;
    }

    int found = 0;
    uint32_t out = 0;
    uint64_t now = now_ms();
    pthread_mutex_lock(&g_cache_mutex);
    for (int i = 0; i < ITER_CACHE_ENTRIES; i++) {
        iterative_cache_entry_t *e = &g_cache[i];
        if (!e->in_use) {
            continue;
        }
        if (e->expires_at_ms <= now) {
            e->in_use = 0;
            continue;
        }
        if (strcmp(e->host, host) == 0) {
            out = e->addr_v4_be;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_cache_mutex);

    if (found) {
        *addr_v4_be_out = out;
        return 1;
    }
    return 0;
}

static void cache_store(const char *host, uint32_t addr_v4_be, uint32_t ttl_seconds) {
    if (host == NULL || *host == '\0') {
        return;
    }

    uint64_t ttl_ms = ttl_seconds == 0 ? ITER_CACHE_TTL_FALLBACK_MS : (uint64_t)ttl_seconds * 1000ULL;
    if (ttl_ms < ITER_CACHE_TTL_MIN_MS) {
        ttl_ms = ITER_CACHE_TTL_MIN_MS;
    }
    if (ttl_ms > ITER_CACHE_TTL_MAX_MS) {
        ttl_ms = ITER_CACHE_TTL_MAX_MS;
    }

    uint64_t now = now_ms();
    int free_idx = -1;

    pthread_mutex_lock(&g_cache_mutex);
    for (int i = 0; i < ITER_CACHE_ENTRIES; i++) {
        iterative_cache_entry_t *e = &g_cache[i];
        if (!e->in_use || e->expires_at_ms <= now) {
            if (free_idx < 0) {
                free_idx = i;
            }
            e->in_use = 0;
            continue;
        }
        if (strcmp(e->host, host) == 0) {
            e->addr_v4_be = addr_v4_be;
            e->expires_at_ms = now + ttl_ms;
            pthread_mutex_unlock(&g_cache_mutex);
            return;
        }
    }

    if (free_idx < 0) {
        free_idx = 0;
    }

    iterative_cache_entry_t *dst = &g_cache[free_idx];
    snprintf(dst->host, sizeof(dst->host), "%s", host);
    dst->addr_v4_be = addr_v4_be;
    dst->expires_at_ms = now + ttl_ms;
    dst->in_use = 1;
    pthread_mutex_unlock(&g_cache_mutex);
}

static int ns_name_present(parsed_response_t *parsed, const char *name) {
    if (parsed == NULL || name == NULL) {
        return 0;
    }
    for (int i = 0; i < parsed->ns_name_count; i++) {
        if (strcmp(parsed->ns_names[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int build_query_packet(
    const char *name,
    uint16_t qtype,
    uint16_t txid,
    uint8_t *out,
    size_t out_len,
    size_t *written_out) {
    if (name == NULL || out == NULL || written_out == NULL || out_len < DNS_HEADER_SIZE + 6) {
        return -1;
    }

    memset(out, 0, out_len);
    write_u16(out + 0, txid);
    write_u16(out + 2, 0x0000u); /* QR=0, RD=0 iterative */
    write_u16(out + 4, 1);

    size_t off = DNS_HEADER_SIZE;
    size_t name_len = 0;
    if (encode_qname(name, out + off, out_len - off, &name_len) != 0) {
        return -1;
    }
    off += name_len;
    if (off + 4 > out_len) {
        return -1;
    }
    write_u16(out + off, qtype);
    write_u16(out + off + 2, DNS_CLASS_IN);
    off += 4;
    *written_out = off;
    return 0;
}

static int send_udp_query(
    uint32_t ns_ip_be,
    const char *name,
    uint16_t qtype,
    int timeout_ms,
    uint8_t *resp,
    size_t resp_cap,
    size_t *resp_len_out,
    int *truncated_out) {
    if (name == NULL || resp == NULL || resp_len_out == NULL || resp_cap < DNS_HEADER_SIZE || truncated_out == NULL) {
        return -1;
    }

    *truncated_out = 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = ns_ip_be;

    uint8_t query[512];
    uint16_t txid = (uint16_t)((unsigned int)rand() & 0xffffu);
    size_t qlen = 0;
    if (build_query_packet(name, qtype, txid, query, sizeof(query), &qlen) != 0) {
        close(fd);
        return -1;
    }

    ssize_t sent = sendto(fd, query, qlen, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent != (ssize_t)qlen) {
        close(fd);
        return -1;
    }

    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int prc = poll(&pfd, 1, timeout_ms);
    if (prc <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        close(fd);
        return -1;
    }

    ssize_t n = recvfrom(fd, resp, resp_cap, 0, NULL, NULL);
    close(fd);
    if (n < (ssize_t)DNS_HEADER_SIZE) {
        return -1;
    }

    if (read_u16(resp + 0) != txid) {
        return -1;
    }
    if ((read_u16(resp + 2) & 0x8000u) == 0) {
        return -1;
    }
    if ((read_u16(resp + 2) & 0x0200u) != 0) {
        *truncated_out = 1;
        return 0;
    }

    *resp_len_out = (size_t)n;
    return 0;
}

static int send_all_with_timeout(int fd, const uint8_t *buf, size_t len, int timeout_ms) {
    size_t off = 0;
    while (off < len) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            return -1;
        }
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int recv_all_with_timeout(int fd, uint8_t *buf, size_t len, int timeout_ms) {
    size_t off = 0;
    while (off < len) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            return -1;
        }
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int send_tcp_query(
    uint32_t ns_ip_be,
    const char *name,
    uint16_t qtype,
    int timeout_ms,
    uint8_t *resp,
    size_t resp_cap,
    size_t *resp_len_out) {
    if (name == NULL || resp == NULL || resp_len_out == NULL || resp_cap < DNS_HEADER_SIZE) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = ns_ip_be;

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (rc != 0) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            close(fd);
            return -1;
        }

        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
            close(fd);
            return -1;
        }
    }

    if (fcntl(fd, F_SETFL, flags) != 0) {
        close(fd);
        return -1;
    }

    uint8_t query[512];
    uint16_t txid = (uint16_t)((unsigned int)rand() & 0xffffu);
    size_t qlen = 0;
    if (build_query_packet(name, qtype, txid, query, sizeof(query), &qlen) != 0) {
        close(fd);
        return -1;
    }

    uint8_t len_prefix[2];
    write_u16(len_prefix, (uint16_t)qlen);
    if (send_all_with_timeout(fd, len_prefix, sizeof(len_prefix), timeout_ms) != 0 ||
        send_all_with_timeout(fd, query, qlen, timeout_ms) != 0) {
        close(fd);
        return -1;
    }

    uint8_t resp_len_prefix[2];
    if (recv_all_with_timeout(fd, resp_len_prefix, sizeof(resp_len_prefix), timeout_ms) != 0) {
        close(fd);
        return -1;
    }

    uint16_t msg_len = read_u16(resp_len_prefix);
    if (msg_len < DNS_HEADER_SIZE || msg_len > resp_cap) {
        close(fd);
        return -1;
    }

    if (recv_all_with_timeout(fd, resp, msg_len, timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    close(fd);

    if (read_u16(resp + 0) != txid) {
        return -1;
    }
    if ((read_u16(resp + 2) & 0x8000u) == 0) {
        return -1;
    }

    *resp_len_out = msg_len;
    return 0;
}

static int parse_response_for_name(
    const uint8_t *msg,
    size_t msg_len,
    const char *qname,
    parsed_response_t *parsed) {
    if (msg == NULL || parsed == NULL || qname == NULL || msg_len < DNS_HEADER_SIZE) {
        return -1;
    }

    memset(parsed, 0, sizeof(*parsed));

    uint16_t flags = read_u16(msg + 2);
    uint16_t rcode = (uint16_t)(flags & 0x000fu);
    if (rcode != 0 && rcode != 3) {
        return -1;
    }
    if (rcode == 3) {
        return 0;
    }

    uint16_t qdcount = read_u16(msg + 4);
    uint16_t ancount = read_u16(msg + 6);
    uint16_t nscount = read_u16(msg + 8);
    uint16_t arcount = read_u16(msg + 10);

    size_t off = DNS_HEADER_SIZE;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (skip_name(msg, msg_len, &off) != 0 || off + 4 > msg_len) {
            return -1;
        }
        off += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        char rr_name[256];
        if (read_name(msg, msg_len, &off, rr_name, sizeof(rr_name)) != 0 || off + 10 > msg_len) {
            return -1;
        }
        uint16_t type = read_u16(msg + off + 0);
        uint16_t klass = read_u16(msg + off + 2);
        uint32_t ttl = ((uint32_t)msg[off + 4] << 24) |
                       ((uint32_t)msg[off + 5] << 16) |
                       ((uint32_t)msg[off + 6] << 8) |
                       (uint32_t)msg[off + 7];
        uint16_t rdlen = read_u16(msg + off + 8);
        off += 10;
        if (off + rdlen > msg_len) {
            return -1;
        }

        if (klass == DNS_CLASS_IN && type == DNS_TYPE_A && rdlen == 4 && strcmp(rr_name, qname) == 0) {
            memcpy(&parsed->a_addr_be, msg + off, 4);
            parsed->got_a = 1;
            parsed->a_ttl = ttl;
            return 0;
        }

        if (klass == DNS_CLASS_IN && type == DNS_TYPE_CNAME) {
            size_t cname_off = off;
            (void)read_name(msg, msg_len, &cname_off, parsed->cname_target, sizeof(parsed->cname_target));
        }
        off += rdlen;
    }

    for (uint16_t i = 0; i < nscount; i++) {
        if (skip_name(msg, msg_len, &off) != 0 || off + 10 > msg_len) {
            return -1;
        }
        uint16_t type = read_u16(msg + off + 0);
        uint16_t klass = read_u16(msg + off + 2);
        uint16_t rdlen = read_u16(msg + off + 8);
        off += 10;
        if (off + rdlen > msg_len) {
            return -1;
        }

        if (klass == DNS_CLASS_IN && type == DNS_TYPE_NS && parsed->ns_name_count < ITER_MAX_NS) {
            size_t ns_off = off;
            if (read_name(msg, msg_len, &ns_off, parsed->ns_names[parsed->ns_name_count], sizeof(parsed->ns_names[0])) == 0) {
                parsed->ns_name_count++;
            }
        }
        off += rdlen;
    }

    for (uint16_t i = 0; i < arcount; i++) {
        char rr_name[256];
        if (read_name(msg, msg_len, &off, rr_name, sizeof(rr_name)) != 0 || off + 10 > msg_len) {
            return -1;
        }
        uint16_t type = read_u16(msg + off + 0);
        uint16_t klass = read_u16(msg + off + 2);
        uint16_t rdlen = read_u16(msg + off + 8);
        off += 10;
        if (off + rdlen > msg_len) {
            return -1;
        }

        if (klass == DNS_CLASS_IN && type == DNS_TYPE_A && rdlen == 4 && ns_name_present(parsed, rr_name)) {
            if (parsed->glue_count < ITER_MAX_NS) {
                memcpy(&parsed->glue_ips[parsed->glue_count], msg + off, 4);
                parsed->glue_count++;
            }
        }

        off += rdlen;
    }

    return 0;
}

static int iterative_resolve_a_internal(
    const char *hostname,
    uint64_t deadline_ms,
    int depth,
    uint32_t *addr_v4_be_out,
    uint32_t *ttl_out) {
    if (hostname == NULL || addr_v4_be_out == NULL || depth > ITER_MAX_DEPTH) {
        return -1;
    }

    ip_list_t current;
    memset(&current, 0, sizeof(current));
    for (size_t i = 0; i < sizeof(k_root_servers) / sizeof(k_root_servers[0]); i++) {
        struct in_addr a;
        if (inet_pton(AF_INET, k_root_servers[i], &a) == 1) {
            (void)ip_list_add(&current, a.s_addr);
        }
    }

    for (int hop = 0; hop < ITER_MAX_HOPS && current.count > 0; hop++) {
        ip_list_t next;
        memset(&next, 0, sizeof(next));

        for (int i = 0; i < current.count; i++) {
            uint64_t now = now_ms();
            if (now >= deadline_ms) {
                return -1;
            }
            int remaining_ms = (int)(deadline_ms - now);
            int per_query_timeout = remaining_ms > 700 ? 700 : remaining_ms;
            if (per_query_timeout < 100) {
                per_query_timeout = remaining_ms;
            }
            if (per_query_timeout <= 0) {
                return -1;
            }

            uint8_t resp[DNS_MAX_PACKET];
            size_t resp_len = 0;
            int truncated = 0;
            if (send_udp_query(
                    current.ips[i],
                    hostname,
                    DNS_TYPE_A,
                    per_query_timeout,
                    resp,
                    sizeof(resp),
                    &resp_len,
                    &truncated)
                != 0) {
                continue;
            }

            if (truncated) {
                if (send_tcp_query(current.ips[i], hostname, DNS_TYPE_A, per_query_timeout, resp, sizeof(resp), &resp_len) != 0) {
                    continue;
                }
            }

            parsed_response_t parsed;
            if (parse_response_for_name(resp, resp_len, hostname, &parsed) != 0) {
                continue;
            }

            if (parsed.got_a) {
                *addr_v4_be_out = parsed.a_addr_be;
                if (ttl_out != NULL) {
                    *ttl_out = parsed.a_ttl;
                }
                return 0;
            }

            if (parsed.glue_count > 0) {
                for (int g = 0; g < parsed.glue_count; g++) {
                    (void)ip_list_add(&next, parsed.glue_ips[g]);
                }
                continue;
            }

            for (int n = 0; n < parsed.ns_name_count; n++) {
                uint32_t ns_ip = 0;
                if (iterative_resolve_a_internal(parsed.ns_names[n], deadline_ms, depth + 1, &ns_ip, NULL) == 0) {
                    (void)ip_list_add(&next, ns_ip);
                }
            }

            if (parsed.cname_target[0] != '\0') {
                if (iterative_resolve_a_internal(parsed.cname_target, deadline_ms, depth + 1, addr_v4_be_out, ttl_out) == 0) {
                    return 0;
                }
            }
        }

        current = next;
    }

    return -1;
}

int iterative_resolve_a(const char *hostname, int timeout_ms, uint32_t *addr_v4_be_out) {
    if (hostname == NULL || addr_v4_be_out == NULL) {
        return -1;
    }

    char normalized[256];
    if (normalize_hostname(hostname, normalized, sizeof(normalized)) != 0) {
        return -1;
    }

    if (cache_lookup(normalized, addr_v4_be_out)) {
        return 0;
    }

    int budget_ms = timeout_ms > 0 ? timeout_ms : 2500;
    uint64_t deadline = now_ms() + (uint64_t)budget_ms;
    uint32_t ttl = 0;
    int rc = iterative_resolve_a_internal(normalized, deadline, 0, addr_v4_be_out, &ttl);
    if (rc == 0) {
        cache_store(normalized, *addr_v4_be_out, ttl);
    }
    return rc;
}
