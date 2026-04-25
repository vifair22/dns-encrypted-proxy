#define _POSIX_C_SOURCE 200809L

#include "dns_server.h"

#include "dns_message.h"
#include "logger.h"
#include "upstream_bootstrap.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DNS_MAX_MESSAGE_SIZE 65535
#define CACHE_KEY_MAX_SIZE 4096

typedef struct {
    proxy_server_t *server;
    int fd;
} socket_loop_ctx_t;

typedef struct {
    proxy_server_t *server;
    int client_fd;
    int query_count;
} tcp_client_ctx_t;

static uint64_t monotonic_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void record_internal_error_impl(const char *func, proxy_server_t *server, const char *reason, const char *fmt, ...) {
    if (server != NULL) {
        atomic_fetch_add(&server->metrics.internal_errors_total, 1);
    }

    if (func == NULL || reason == NULL || fmt == NULL) {
        return;
    }

    char detail[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    if (n < 0) {
        logger_logf(func, "ERROR", "Internal error [%s]", reason);
        return;
    }
    logger_logf(func, "ERROR", "Internal error [%s]: %s", reason, detail);
}

#define RECORD_INTERNAL_ERROR(server, reason, fmt, ...) \
    record_internal_error_impl(__func__, (server), (reason), (fmt), ##__VA_ARGS__)

static int should_stop(const proxy_server_t *server) {
    return server->stop_flag != NULL && *server->stop_flag != 0;
}

static uint16_t read_u16(const uint8_t *ptr) {
    return (uint16_t)((ptr[0] << 8) | ptr[1]);
}

static void write_u16(uint8_t *ptr, uint16_t value) {
    ptr[0] = (uint8_t)((value >> 8) & 0xFFu);
    ptr[1] = (uint8_t)(value & 0xFFu);
}

static void write_u32(uint8_t *ptr, uint32_t value) {
    ptr[0] = (uint8_t)((value >> 24) & 0xFFu);
    ptr[1] = (uint8_t)((value >> 16) & 0xFFu);
    ptr[2] = (uint8_t)((value >> 8) & 0xFFu);
    ptr[3] = (uint8_t)(value & 0xFFu);
}

static void metrics_record_response(proxy_server_t *server, const uint8_t *response, size_t response_len) {
    if (server == NULL || response == NULL || response_len < 4) {
        return;
    }

    uint16_t flags = read_u16(response + 2);
    uint16_t rcode = (uint16_t)(flags & 0x000Fu);

    atomic_fetch_add(&server->metrics.responses_total, 1);
    if (rcode < 16) {
        atomic_fetch_add(&server->metrics.responses_rcode[rcode], 1);
    }
}

static int dns_skip_name_wire(const uint8_t *message, size_t message_len, size_t *offset) {
    size_t pos = *offset;
    int steps = 0;

    while (pos < message_len) {
        if (++steps > 255) {
            return -1;
        }

        uint8_t label_len = message[pos];
        if (label_len == 0) {
            *offset = pos + 1;
            return 0;
        }

        if ((label_len & 0xC0u) == 0xC0u) {
            if (pos + 1 >= message_len) {
                return -1;
            }
            *offset = pos + 2;
            return 0;
        }

        if ((label_len & 0xC0u) != 0) {
            return -1;
        }

        pos += 1;
        if (pos + label_len > message_len) {
            return -1;
        }
        pos += label_len;
    }

    return -1;
}

static int dns_rr_end_offset(const uint8_t *message, size_t message_len, size_t rr_start, size_t *rr_end_out) {
    if (message == NULL || rr_end_out == NULL || rr_start >= message_len) {
        return -1;
    }

    size_t offset = rr_start;
    if (dns_skip_name_wire(message, message_len, &offset) != 0) {
        return -1;
    }
    if (offset + 10 > message_len) {
        return -1;
    }

    uint16_t rdlength = read_u16(message + offset + 8);
    offset += 10;
    if (offset + rdlength > message_len) {
        return -1;
    }

    *rr_end_out = offset + rdlength;
    return 0;
}

static int dns_find_query_opt(const uint8_t *query, size_t query_len, size_t *opt_start, size_t *opt_end) {
    if (query_len < 12) {
        return -1;
    }

    uint16_t qdcount = read_u16(query + 4);
    uint16_t arcount = read_u16(query + 10);

    size_t offset = 12;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name_wire(query, query_len, &offset) != 0) {
            return -1;
        }
        if (offset + 4 > query_len) {
            return -1;
        }
        offset += 4;
    }

    for (uint16_t i = 0; i < arcount; i++) {
        size_t rr_start = offset;
        size_t name_end = offset;
        if (dns_skip_name_wire(query, query_len, &name_end) != 0) {
            return -1;
        }
        if (name_end + 10 > query_len) {
            return -1;
        }
        uint16_t rr_type = read_u16(query + name_end);
        uint16_t rdlength = read_u16(query + name_end + 8);
        size_t rr_end = name_end + 10 + rdlength;
        if (rr_end > query_len) {
            return -1;
        }
        if (rr_type == 41) {
            if (opt_start) *opt_start = rr_start;
            if (opt_end) *opt_end = rr_end;
            return 0;
        }
        offset = rr_end;
    }
    return -1;
}

static int dns_extract_single_question_name_a(
    const uint8_t *query,
    size_t query_len,
    char *name_out,
    size_t name_out_len,
    size_t *question_end_out) {
    if (query == NULL || query_len < 12 || name_out == NULL || name_out_len == 0 || question_end_out == NULL) {
        return -1;
    }

    if (read_u16(query + 4) != 1) {
        return -1;
    }

    size_t offset = 12;
    size_t out_len = 0;
    int label_count = 0;

    while (offset < query_len) {
        uint8_t label_len = query[offset++];
        if (label_len == 0) {
            break;
        }
        if (label_len > 63 || (label_len & 0xC0u) != 0) {
            return -1;
        }
        if (offset + label_len > query_len) {
            return -1;
        }
        if (label_count > 0) {
            if (out_len + 1 >= name_out_len) {
                return -1;
            }
            name_out[out_len++] = '.';
        }
        for (uint8_t i = 0; i < label_len; i++) {
            uint8_t ch = query[offset + i];
            if (ch >= 'A' && ch <= 'Z') {
                ch = (uint8_t)(ch - 'A' + 'a');
            }
            if (out_len + 1 >= name_out_len) {
                return -1;
            }
            name_out[out_len++] = (char)ch;
        }
        offset += label_len;
        label_count++;
    }

    if (offset + 4 > query_len) {
        return -1;
    }

    uint16_t qtype = read_u16(query + offset);
    uint16_t qclass = read_u16(query + offset + 2);
    if (qtype != 1 || qclass != 1) {
        return -1;
    }

    name_out[out_len] = '\0';
    *question_end_out = offset + 4;
    return 0;
}

static int build_hosts_a_response(
    const uint8_t *query,
    size_t query_len,
    uint32_t addr_v4_be,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (query == NULL || query_len < 12 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    size_t question_end = 0;
    char unused_name[256];
    if (dns_extract_single_question_name_a(query, query_len, unused_name, sizeof(unused_name), &question_end) != 0) {
        return -1;
    }

    size_t question_len = question_end - 12;
    size_t opt_start = 0;
    size_t opt_end = 0;
    int has_opt = (dns_find_query_opt(query, query_len, &opt_start, &opt_end) == 0);
    size_t opt_len = has_opt ? (opt_end - opt_start) : 0;

    size_t answer_len = 16;
    size_t response_len = 12 + question_len + answer_len + opt_len;
    uint8_t *response = calloc(1, response_len);
    if (response == NULL) {
        return -1;
    }

    response[0] = query[0];
    response[1] = query[1];

    uint16_t query_flags = read_u16(query + 2);
    uint16_t response_flags = (uint16_t)(0x8000u | (query_flags & 0x7800u) | (query_flags & 0x0100u) | (query_flags & 0x0010u) | 0x0080u);
    write_u16(response + 2, response_flags);
    write_u16(response + 4, 1);
    write_u16(response + 6, 1);
    write_u16(response + 8, 0);
    write_u16(response + 10, has_opt ? 1 : 0);

    memcpy(response + 12, query + 12, question_len);

    size_t ans = 12 + question_len;
    response[ans + 0] = 0xC0;
    response[ans + 1] = 0x0C;
    write_u16(response + ans + 2, 1);
    write_u16(response + ans + 4, 1);
    write_u32(response + ans + 6, 60);
    write_u16(response + ans + 10, 4);
    memcpy(response + ans + 12, &addr_v4_be, 4);

    if (has_opt) {
        memcpy(response + ans + answer_len, query + opt_start, opt_len);
    }

    *response_out = response;
    *response_len_out = response_len;
    return 0;
}

static int build_servfail_response(const uint8_t *query, size_t query_len, uint8_t **response_out, size_t *response_len_out) {
    if (query_len < 12 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    size_t question_len = 0;
    if (dns_question_section_length(query, query_len, &question_len) != 0) {
        return -1;
    }

    size_t opt_start = 0, opt_end = 0;
    int has_opt = (dns_find_query_opt(query, query_len, &opt_start, &opt_end) == 0);
    size_t opt_len = has_opt ? (opt_end - opt_start) : 0;

    size_t response_len = 12 + question_len + opt_len;
    uint8_t *response = calloc(1, response_len);
    if (response == NULL) {
        return -1;
    }

    response[0] = query[0];
    response[1] = query[1];

    /*
     * SERVFAIL construction mirrors request identity and policy bits (opcode,
     * RD/CD) so clients can safely correlate retries. If query carried OPT,
     * we preserve it to keep EDNS negotiation behavior predictable.
     */
    uint16_t query_flags = read_u16(query + 2);
    uint16_t response_flags = (uint16_t)(0x8000u | (query_flags & 0x7800u) | (query_flags & 0x0100u) | (query_flags & 0x0010u) |
                                         0x0080u | 0x0002u);
    write_u16(response + 2, response_flags);

    uint16_t qdcount = read_u16(query + 4);
    write_u16(response + 4, qdcount);
    write_u16(response + 6, 0);
    write_u16(response + 8, 0);
    write_u16(response + 10, has_opt ? 1 : 0);

    if (question_len > 0) {
        memcpy(response + 12, query + 12, question_len);
    }

    if (has_opt) {
        memcpy(response + 12 + question_len, query + opt_start, opt_len);
    }

    *response_out = response;
    *response_len_out = response_len;
    return 0;
}

#define DNS_TYPE_OPT 41

static int dns_find_opt_record(
    const uint8_t *message,
    size_t message_len,
    size_t *opt_start_out,
    size_t *opt_end_out) {
    if (message == NULL || message_len < 12) {
        return -1;
    }

    uint16_t qdcount = read_u16(message + 4);
    uint16_t ancount = read_u16(message + 6);
    uint16_t nscount = read_u16(message + 8);
    uint16_t arcount = read_u16(message + 10);

    size_t offset = 12;

    for (uint16_t i = 0; i < qdcount; i++) {
        if (dns_skip_name_wire(message, message_len, &offset) != 0) {
            return -1;
        }
        if (offset + 4 > message_len) {
            return -1;
        }
        offset += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        size_t rr_end = 0;
        if (dns_rr_end_offset(message, message_len, offset, &rr_end) != 0) {
            return -1;
        }
        offset = rr_end;
    }

    for (uint16_t i = 0; i < nscount; i++) {
        size_t rr_end = 0;
        if (dns_rr_end_offset(message, message_len, offset, &rr_end) != 0) {
            return -1;
        }
        offset = rr_end;
    }

    for (uint16_t i = 0; i < arcount; i++) {
        size_t rr_start = offset;
        size_t name_end = offset;
        if (dns_skip_name_wire(message, message_len, &name_end) != 0) {
            return -1;
        }
        if (name_end + 10 > message_len) {
            return -1;
        }

        uint16_t rr_type = read_u16(message + name_end);
        uint16_t rdlength = read_u16(message + name_end + 8);
        size_t rr_end = name_end + 10 + rdlength;
        if (rr_end > message_len) {
            return -1;
        }

        if (rr_type == DNS_TYPE_OPT) {
            if (opt_start_out != NULL) {
                *opt_start_out = rr_start;
            }
            if (opt_end_out != NULL) {
                *opt_end_out = rr_end;
            }
            return 0;
        }

        offset = rr_end;
    }

    return -1;
}

static int build_truncated_udp_response(
    const uint8_t *response,
    size_t response_len,
    size_t udp_limit,
    uint8_t **truncated_out,
    size_t *truncated_len_out) {
    if (response == NULL || truncated_out == NULL || truncated_len_out == NULL || response_len < 12) {
        return -1;
    }

    /* Never emit less than DNS header size. */
    if (udp_limit < 12) {
        udp_limit = 12;
    }

    uint16_t original_qd = read_u16(response + 4);
    uint16_t original_an = read_u16(response + 6);
    uint16_t original_ns = read_u16(response + 8);
    uint16_t original_ar = read_u16(response + 10);

    size_t offset = 12;
    size_t include_end = 12;
    uint16_t include_qd = 0;
    uint16_t include_an = 0;
    uint16_t include_ns = 0;
    uint16_t include_ar = 0;

    int malformed = 0;
    int is_truncated = 0;

    size_t opt_start = 0;
    size_t opt_end = 0;
    int has_opt = (dns_find_opt_record(response, response_len, &opt_start, &opt_end) == 0);
    size_t opt_size = has_opt ? (opt_end - opt_start) : 0;

    /*
     * We preserve as much structure as possible in order:
     *  1) full questions first
     *  2) then RR sections in canonical order until limit
     *  3) optional OPT only if it still fits
     */
    for (uint16_t i = 0; i < original_qd; i++) {
        size_t name_end = offset;
        if (dns_skip_name_wire(response, response_len, &name_end) != 0 || name_end + 4 > response_len) {
            malformed = 1;
            break;
        }

        size_t question_end = name_end + 4;
        if (question_end > udp_limit) {
            is_truncated = 1;
            goto finalize;
        }

        include_qd++;
        include_end = question_end;
        offset = question_end;
    }

    if (malformed) {
        goto finalize;
    }

    uint16_t section_counts[3] = {original_an, original_ns, original_ar};
    uint16_t *include_counts[3] = {&include_an, &include_ns, &include_ar};

    for (int section = 0; section < 3; section++) {
        for (uint16_t i = 0; i < section_counts[section]; i++) {
            size_t rr_start = offset;
            size_t rr_end = 0;
            if (dns_rr_end_offset(response, response_len, offset, &rr_end) != 0) {
                malformed = 1;
                break;
            }

            if (has_opt && rr_start == opt_start) {
                offset = rr_end;
                continue;
            }

            if (rr_end > udp_limit) {
                is_truncated = 1;
                goto finalize;
            }

            (*include_counts[section])++;
            include_end = rr_end;
            offset = rr_end;
        }

        if (malformed) {
            break;
        }
    }

    if (!malformed && include_end < response_len) {
        is_truncated = 1;
    }

finalize:
    /* Caller only uses this helper on oversized/problem responses. */
    if (!is_truncated && !malformed) {
        return -1;
    }
    if (malformed) {
        include_end = 12;
        include_qd = 0;
        include_an = 0;
        include_ns = 0;
        include_ar = 0;
        has_opt = 0;
    }

    int include_opt = 0;
    if (has_opt && !malformed) {
        if (include_end + opt_size <= udp_limit) {
            include_opt = 1;
        }
    }

    /* include_end is always >= 12 here (DNS header size): initialized to 12,
     * only ever set to rr_end (>= header) or back to 12 in the malformed
     * branch. The assert documents the invariant for future readers; the
     * NOLINT below covers the same write_u16 calls because clang-analyzer
     * can't propagate the assert through the call chain.
     */
    assert(include_end >= 12);
    size_t total_size = include_end + (include_opt ? opt_size : 0);
    uint8_t *truncated = malloc(total_size);
    if (truncated == NULL) {
        return -1;
    }

    memcpy(truncated, response, include_end);

    if (include_opt) {
        memcpy(truncated + include_end, response + opt_start, opt_size);
        include_ar++; /* Count the OPT record in additional section */
    }

    uint16_t flags = read_u16(truncated + 2);
    flags = (uint16_t)(flags | 0x0200u); /* TC */
    /* total_size is always >= 12 (asserted above); writing the 12-byte DNS
     * header is safe but clang-analyzer can't propagate the invariant
     * through the call chain into write_u16. */
    // NOLINTBEGIN(clang-analyzer-security.ArrayBound)
    write_u16(truncated + 2, flags);
    write_u16(truncated + 4, include_qd);
    write_u16(truncated + 6, include_an);
    write_u16(truncated + 8, include_ns);
    write_u16(truncated + 10, include_ar);
    // NOLINTEND(clang-analyzer-security.ArrayBound)

    *truncated_out = truncated;
    *truncated_len_out = total_size;
    return 0;
}

static int process_query(proxy_server_t *server, const uint8_t *query, size_t query_len, uint8_t **response_out, size_t *response_len_out) {
    if (server == NULL || query == NULL || query_len < 12 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    uint64_t request_start_ms = monotonic_now_ms();

    uint8_t key[CACHE_KEY_MAX_SIZE];
    size_t key_len = 0;
    int key_ok = (dns_extract_question_key(query, query_len, key, sizeof(key), &key_len) == 0);

    const uint8_t request_id[2] = {query[0], query[1]};

    char qname[256];
    size_t question_end = 0;
    if (dns_extract_single_question_name_a(query, query_len, qname, sizeof(qname), &question_end) == 0) {
        uint32_t addr_v4_be = 0;
        if (config_lookup_hosts_a(&server->config, qname, &addr_v4_be)) {
            if (build_hosts_a_response(query, query_len, addr_v4_be, response_out, response_len_out) == 0) {
                return 0;
            }
        }
    }

    /*
     * Reject malformed/unkeyable queries before upstream dispatch.
     * This avoids forwarding invalid DNS payloads that DoH providers return as
     * HTTP 400/413 and keeps upstream health accounting meaningful.
     */
    if (!key_ok) {
        atomic_fetch_add(&server->metrics.servfail_sent, 1);
        if (build_servfail_response(query, query_len, response_out, response_len_out) != 0) {
            RECORD_INTERNAL_ERROR(server, "servfail_build_failed", "invalid_query_len=%zu", query_len);
            return -1;
        }
        return 0;
    }

    if (dns_cache_lookup(&server->cache, key, key_len, request_id, response_out, response_len_out)) {
        atomic_fetch_add(&server->metrics.cache_hits, 1);
        return 0;
    }
    atomic_fetch_add(&server->metrics.cache_misses, 1);

    int upstream_budget_ms = server->config.upstream_timeout_ms;
    if (upstream_budget_ms <= 0) {
        upstream_budget_ms = 1000;
    }
    uint64_t request_deadline_ms = request_start_ms + (uint64_t)upstream_budget_ms;

    if (upstream_facilitator_resolve_with_deadline(
            &server->upstream_facilitator,
            query,
            query_len,
            request_deadline_ms,
            response_out,
            response_len_out)
        == 0) {
        atomic_fetch_add(&server->metrics.upstream_success, 1);
        /* Upstream response ID is rewritten to client request ID at edge. */
        if (*response_len_out >= 2) {
            (*response_out)[0] = query[0];
            (*response_out)[1] = query[1];
        }

        /* Cache only policy-approved responses with meaningful TTL. */
        if (dns_response_is_cacheable(*response_out, *response_len_out)) {
            int ttl_ok = 0;
            uint32_t min_ttl = dns_response_min_ttl(*response_out, *response_len_out, &ttl_ok);
            if (ttl_ok && min_ttl > 0) {
                dns_cache_store(&server->cache, key, key_len, *response_out, *response_len_out, min_ttl);
            }
        }

        return 0;
    }

    atomic_fetch_add(&server->metrics.upstream_failures, 1);
    atomic_fetch_add(&server->metrics.servfail_sent, 1);
    if (build_servfail_response(query, query_len, response_out, response_len_out) != 0) {
        RECORD_INTERNAL_ERROR(server, "servfail_build_failed", "query_len=%zu", query_len);
        return -1;
    }
    return 0;
}

static int create_udp_socket(const proxy_config_t *config) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)config->listen_port);

    if (inet_pton(AF_INET, config->listen_addr, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int create_tcp_socket(const proxy_config_t *config) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)config->listen_port);

    if (inet_pton(AF_INET, config->listen_addr, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 128) != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void *udp_loop(void *arg) {
    socket_loop_ctx_t *ctx = (socket_loop_ctx_t *)arg;
    proxy_server_t *server = ctx->server;
    int fd = ctx->fd;
    const char *exit_reason = "stop_requested";

    /* One-time lifecycle log; avoid per-query noise. */
    LOGF_INFO("UDP loop thread started");

    uint8_t *buffer = (uint8_t *)malloc(DNS_MAX_MESSAGE_SIZE);
    if (buffer == NULL) {
        LOGF_ERROR("UDP loop failed to allocate receive buffer");
        return NULL;
    }

    while (!should_stop(server)) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLIN;

        int poll_rc = poll(&pfd, 1, 500);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            exit_reason = "poll_error";
            break;
        }
        if (poll_rc == 0) {
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            exit_reason = "poll_revents_error";
            break;
        }
        if ((pfd.revents & POLLIN) == 0) {
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t n = recvfrom(fd, buffer, DNS_MAX_MESSAGE_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (n <= 0) {
            continue;
        }
        if (n < 12) {
            continue;
        }
        atomic_fetch_add(&server->metrics.queries_udp, 1);

        uint8_t *response = NULL;
        size_t response_len = 0;
        if (process_query(server, buffer, (size_t)n, &response, &response_len) != 0) {
            RECORD_INTERNAL_ERROR(server, "process_query_failed", "udp_query_len=%zd", n);
            continue;
        }

        if (response != NULL && response_len > 0) {
            /*
             * UDP response sizing policy:
             * - honor query-advertised payload limit (EDNS when present)
             * - prefer TC=1 truncation so standards-compliant clients retry TCP
             * - fall back to SERVFAIL only if truncation packet build fails
             */
            size_t udp_limit = dns_udp_payload_limit_for_query(buffer, (size_t)n);
            if (response_len > udp_limit) {
                uint8_t *truncated = NULL;
                size_t truncated_len = 0;
                if (build_truncated_udp_response(response, response_len, udp_limit, &truncated, &truncated_len) == 0) {
                    free(response);
                    response = truncated;
                    response_len = truncated_len;
                    atomic_fetch_add(&server->metrics.truncated_sent, 1);
                } else {
                    free(response);
                    response = NULL;
                    response_len = 0;
                    if (build_servfail_response(buffer, (size_t)n, &response, &response_len) != 0) {
                        RECORD_INTERNAL_ERROR(server, "truncation_and_servfail_build_failed", "udp_limit=%zu response_len=%zu", udp_limit, response_len);
                        continue;
                    }
                    atomic_fetch_add(&server->metrics.servfail_sent, 1);
                }
            }

            ssize_t sent = sendto(fd, response, response_len, 0, (struct sockaddr *)&client_addr, client_len);
            if (sent == (ssize_t)response_len) {
                metrics_record_response(server, response, response_len);
            }
            free(response);
        }
    }

    free(buffer);
    if (strcmp(exit_reason, "stop_requested") == 0) {
        LOGF_INFO("UDP loop thread stopped");
    } else {
        LOGF_ERROR("UDP loop thread exiting due to %s", exit_reason);
    }
    return NULL;
}

static int recv_all_with_timeout(int fd, uint8_t *buffer, size_t len, int timeout_ms) {
    /*
     * Return contract is tri-state for callers:
     *  1  => full buffer read
     *  0  => peer closed cleanly
     * -2  => idle timeout
     * -1  => hard I/O or poll error
     */
    size_t offset = 0;
    while (offset < len) {
        if (timeout_ms > 0) {
            struct pollfd pfd = {0};
            pfd.fd = fd;
            pfd.events = POLLIN;

            int poll_rc = poll(&pfd, 1, timeout_ms);
            if (poll_rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (poll_rc == 0) {
                return -2;
            }
            if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return -1;
            }
            if ((pfd.revents & POLLIN) == 0) {
                continue;
            }
        }

        ssize_t n = recv(fd, buffer + offset, len - offset, 0);
        if (n == 0) {
            return 0;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)n;
    }
    return 1;
}

static int send_all(int fd, const uint8_t *buffer, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = send(fd, buffer + offset, len - offset, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)n;
    }
    return 0;
}

static void *tcp_client_loop(void *arg) {
    tcp_client_ctx_t *ctx = (tcp_client_ctx_t *)arg;
    proxy_server_t *server = ctx->server;
    int client_fd = ctx->client_fd;
    int idle_timeout_ms = server->config.tcp_idle_timeout_ms;
    int max_queries = server->config.tcp_max_queries_per_conn;

    while (!should_stop(server)) {
        if (max_queries > 0 && ctx->query_count >= max_queries) {
            break;
        }

        uint8_t length_prefix[2];
        int rc = recv_all_with_timeout(client_fd, length_prefix, sizeof(length_prefix), idle_timeout_ms);
        if (rc <= 0) {
            break;
        }

        uint16_t message_len = read_u16(length_prefix);
        if (message_len == 0) {
            continue;
        }
        atomic_fetch_add(&server->metrics.queries_tcp, 1);

        uint8_t *query = malloc(message_len);
        if (query == NULL) {
            break;
        }

        /*
         * Body read timeout is capped to prevent a client from sending length
         * then dribbling payload forever, while still respecting configured
         * idle timeout when it is lower.
         */
        int body_timeout_ms = idle_timeout_ms > 0 ? (idle_timeout_ms < 5000 ? idle_timeout_ms : 5000) : 0;
        rc = recv_all_with_timeout(client_fd, query, message_len, body_timeout_ms);
        if (rc <= 0) {
            free(query);
            break;
        }

        uint8_t *response = NULL;
        size_t response_len = 0;
        if (process_query(server, query, message_len, &response, &response_len) != 0) {
            RECORD_INTERNAL_ERROR(server, "process_query_failed", "tcp_query_len=%u", (unsigned int)message_len);
            free(query);
            break;
        }

        free(query);
        ctx->query_count++;

        if (response == NULL || response_len == 0 || response_len > UINT16_MAX) {
            free(response);
            break;
        }

        uint8_t out_len[2];
        write_u16(out_len, (uint16_t)response_len);

        if (send_all(client_fd, out_len, sizeof(out_len)) != 0 || send_all(client_fd, response, response_len) != 0) {
            free(response);
            break;
        }

        metrics_record_response(server, response, response_len);

        free(response);
    }

    close(client_fd);
    atomic_fetch_sub(&server->active_tcp_clients, 1);
    atomic_fetch_sub(&server->metrics.tcp_connections_active, 1);
    free(ctx);
    return NULL;
}

static void *tcp_accept_loop(void *arg) {
    socket_loop_ctx_t *ctx = (socket_loop_ctx_t *)arg;
    proxy_server_t *server = ctx->server;
    int fd = ctx->fd;
    int max_clients = server->config.tcp_max_clients;
    const char *exit_reason = "stop_requested";

    /* One-time lifecycle log for accept thread health. */
    LOGF_INFO("TCP accept loop thread started");

    while (!should_stop(server)) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLIN;

        int poll_rc = poll(&pfd, 1, 500);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            exit_reason = "poll_error";
            break;
        }
        if (poll_rc == 0) {
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            exit_reason = "poll_revents_error";
            break;
        }
        if ((pfd.revents & POLLIN) == 0) {
            continue;
        }

        /*
         * Backpressure strategy: accept-and-close when saturated so kernel
         * listen backlog does not hide overload and clients fail fast.
         */
        int current_clients = atomic_load(&server->active_tcp_clients);
        if (current_clients >= max_clients) {
            int client_fd = accept(fd, NULL, NULL);
            if (client_fd >= 0) {
                close(client_fd);
            }
            atomic_fetch_add(&server->metrics.tcp_connections_rejected, 1);
            continue;
        }

        int client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            continue;
        }

        atomic_fetch_add(&server->active_tcp_clients, 1);
        atomic_fetch_add(&server->metrics.tcp_connections_total, 1);
        atomic_fetch_add(&server->metrics.tcp_connections_active, 1);

        tcp_client_ctx_t *client_ctx = calloc(1, sizeof(*client_ctx));
        if (client_ctx == NULL) {
            close(client_fd);
            atomic_fetch_sub(&server->active_tcp_clients, 1);
            atomic_fetch_sub(&server->metrics.tcp_connections_active, 1);
            continue;
        }

        client_ctx->server = server;
        client_ctx->client_fd = client_fd;
        client_ctx->query_count = 0;

        pthread_t thread;
        if (pthread_create(&thread, NULL, tcp_client_loop, client_ctx) != 0) {
            LOGF_ERROR("Failed to create TCP client thread");
            close(client_fd);
            atomic_fetch_sub(&server->active_tcp_clients, 1);
            atomic_fetch_sub(&server->metrics.tcp_connections_active, 1);
            free(client_ctx);
            continue;
        }
        pthread_detach(thread);
    }

    if (strcmp(exit_reason, "stop_requested") == 0) {
        LOGF_INFO("TCP accept loop thread stopped");
    } else {
        LOGF_ERROR("TCP accept loop thread exiting due to %s", exit_reason);
    }

    return NULL;
}

int proxy_server_init(proxy_server_t *server, const proxy_config_t *config, volatile sig_atomic_t *stop_flag) {
    if (server == NULL || config == NULL) {
        return -1;
    }
    
    memset(server, 0, sizeof(*server));
    server->config = *config;
    server->stop_flag = stop_flag;
    
    /* Initialize cache */
    if (dns_cache_init(&server->cache, (size_t)config->cache_capacity) != PROXY_OK) {
        LOGF_ERROR("Failed to initialize cache: %s", proxy_error_message());
        return -1;
    }
    
    /* Initialize upstream client */
    const char *urls[MAX_UPSTREAMS];
    for (int i = 0; i < config->upstream_count; i++) {
        urls[i] = config->upstream_urls[i];
    }
    
    upstream_config_t upstream_cfg = {
        .timeout_ms = config->upstream_timeout_ms,
        .pool_size = config->upstream_pool_size,
        .max_inflight_doh = config->max_inflight_doh,
        .max_inflight_dot = config->max_inflight_dot,
        .max_inflight_doq = config->max_inflight_doq,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 10000,
        .iterative_bootstrap_enabled = 1,
    };
    
    if (upstream_client_init(&server->upstream, urls, config->upstream_count, &upstream_cfg) != PROXY_OK) {
        LOGF_ERROR("Failed to initialize upstream client: %s", proxy_error_message());
        dns_cache_destroy(&server->cache);
        return -1;
    }

    (void)upstream_bootstrap_configure(&server->upstream, config);

    if (upstream_facilitator_init(&server->upstream_facilitator, &server->upstream) != PROXY_OK) {
        LOGF_ERROR("Failed to initialize upstream facilitator: %s", proxy_error_message());
        upstream_client_destroy(&server->upstream);
        dns_cache_destroy(&server->cache);
        return -1;
    }

    LOGF_INFO("Upstream fallback configuration:");
    LOGF_INFO(
        "  stage2 bootstrap resolvers: count=%d",
        config->bootstrap_resolver_count);
    LOGF_INFO("  stage3 iterative resolver: enabled=%d", upstream_cfg.iterative_bootstrap_enabled);
    
    /* Initialize metrics */
    metrics_init(&server->metrics);
    
    return 0;
}

void proxy_server_destroy(proxy_server_t *server) {
    if (server == NULL) {
        return;
    }
    
    upstream_facilitator_destroy(&server->upstream_facilitator);
    upstream_client_destroy(&server->upstream);
    dns_cache_destroy(&server->cache);
    memset(server, 0, sizeof(*server));
}

int proxy_server_run(proxy_server_t *server) {
    if (server == NULL) {
        return -1;
    }

    int udp_fd = create_udp_socket(&server->config);
    if (udp_fd < 0) {
        LOGF_ERROR("Failed to create/bind UDP socket on %s:%d", server->config.listen_addr, server->config.listen_port);
        return -1;
    }

    int tcp_fd = create_tcp_socket(&server->config);
    if (tcp_fd < 0) {
        LOGF_ERROR("Failed to create/bind TCP socket on %s:%d", server->config.listen_addr, server->config.listen_port);
        close(udp_fd);
        return -1;
    }

    socket_loop_ctx_t udp_ctx = {.server = server, .fd = udp_fd};
    socket_loop_ctx_t tcp_ctx = {.server = server, .fd = tcp_fd};

    pthread_t udp_thread;
    pthread_t tcp_thread;

    /*
     * Both loops run until shared stop flag is set. We join both threads to
     * guarantee sockets and worker lifecycle are fully drained on shutdown.
     */
    if (pthread_create(&udp_thread, NULL, udp_loop, &udp_ctx) != 0) {
        LOGF_ERROR("Failed to create UDP loop thread");
        close(udp_fd);
        close(tcp_fd);
        return -1;
    }

    if (pthread_create(&tcp_thread, NULL, tcp_accept_loop, &tcp_ctx) != 0) {
        LOGF_ERROR("Failed to create TCP accept loop thread");
        close(udp_fd);
        close(tcp_fd);
        pthread_join(udp_thread, NULL);
        return -1;
    }

    pthread_join(udp_thread, NULL);
    pthread_join(tcp_thread, NULL);

    close(udp_fd);
    close(tcp_fd);

    LOGF_INFO("Proxy server shutdown complete");

    return 0;
}
