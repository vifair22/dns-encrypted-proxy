#define _POSIX_C_SOURCE 200809L

#include "upstream_bootstrap.h"

#include "iterative_resolver.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STAGE2_RECURSIVE_RETRY_COOLDOWN_MS 30000ULL
#define STAGE1_CACHE_TTL_MS 60000ULL
#define STAGE2_CACHE_TTL_MIN_MS 5000ULL
#define STAGE2_CACHE_TTL_MAX_MS 3600000ULL
#ifndef BOOTSTRAP_DNS_PORT
#define BOOTSTRAP_DNS_PORT 53
#endif

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int test_force_getaddrinfo_fail(void) {
    const char *v = getenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_GETADDRINFO_FAIL");
    return v != NULL && *v != '\0';
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
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
        if (dot == NULL) {
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
        if ((len & 0xC0u) != 0 || len > 63 || pos + 1 + len > msg_len) {
            return -1;
        }
        pos += 1 + len;
    }
    return -1;
}

static int parse_recursive_a_answer(
    const uint8_t *msg,
    size_t msg_len,
    uint32_t *addr_be_out,
    uint32_t *ttl_out,
    const char **reason_out) {
    if (reason_out != NULL) {
        *reason_out = "invalid_dns_response";
    }
    if (msg == NULL || msg_len < 12 || addr_be_out == NULL || ttl_out == NULL) {
        if (reason_out != NULL) {
            *reason_out = "invalid_input";
        }
        return -1;
    }
    uint16_t flags = read_u16(msg + 2);
    if ((flags & 0x8000u) == 0) {
        return -1;
    }
    uint16_t rcode = (uint16_t)(flags & 0x000fu);
    if (rcode != 0) {
        if (reason_out != NULL) {
            *reason_out = "dns_rcode_nonzero";
        }
        return -1;
    }

    uint16_t qdcount = read_u16(msg + 4);
    uint16_t ancount = read_u16(msg + 6);
    size_t off = 12;
    for (uint16_t i = 0; i < qdcount; i++) {
        if (skip_name(msg, msg_len, &off) != 0 || off + 4 > msg_len) {
            if (reason_out != NULL) {
                *reason_out = "invalid_question_section";
            }
            return -1;
        }
        off += 4;
    }

    for (uint16_t i = 0; i < ancount; i++) {
        if (skip_name(msg, msg_len, &off) != 0 || off + 10 > msg_len) {
            if (reason_out != NULL) {
                *reason_out = "invalid_answer_section";
            }
            return -1;
        }
        uint16_t type = read_u16(msg + off + 0);
        uint16_t klass = read_u16(msg + off + 2);
        uint32_t ttl = read_u32(msg + off + 4);
        uint16_t rdlen = read_u16(msg + off + 8);
        off += 10;
        if (off + rdlen > msg_len) {
            if (reason_out != NULL) {
                *reason_out = "invalid_rdata_length";
            }
            return -1;
        }
        if (type == 1 && klass == 1 && rdlen == 4) {
            memcpy(addr_be_out, msg + off, 4);
            *ttl_out = ttl;
            if (reason_out != NULL) {
                *reason_out = "ok";
            }
            return 0;
        }
        off += rdlen;
    }

    if (reason_out != NULL) {
        *reason_out = "no_a_answer";
    }
    return -1;
}

static int stage2_query_resolver(
    const char *resolver_ip,
    const char *hostname,
    int timeout_ms,
    uint32_t *addr_be_out,
    uint32_t *ttl_out,
    const char **reason_out) {
    if (reason_out != NULL) {
        *reason_out = "stage2_query_failed";
    }
    if (resolver_ip == NULL || hostname == NULL || addr_be_out == NULL || ttl_out == NULL) {
        if (reason_out != NULL) {
            *reason_out = "invalid_input";
        }
        return -1;
    }

    struct in_addr resolver_addr;
    if (inet_pton(AF_INET, resolver_ip, &resolver_addr) != 1) {
        if (reason_out != NULL) {
            *reason_out = "invalid_resolver_ip";
        }
        return -1;
    }

    uint8_t query[512];
    memset(query, 0, sizeof(query));
    uint16_t txid = (uint16_t)((unsigned int)rand() & 0xffffu);
    write_u16(query + 0, txid);
    write_u16(query + 2, 0x0100u); /* RD=1 */
    write_u16(query + 4, 1);

    size_t off = 12;
    size_t qname_len = 0;
    if (encode_qname(hostname, query + off, sizeof(query) - off, &qname_len) != 0) {
        if (reason_out != NULL) {
            *reason_out = "invalid_hostname";
        }
        return -1;
    }
    off += qname_len;
    if (off + 4 > sizeof(query)) {
        if (reason_out != NULL) {
            *reason_out = "query_buffer_overflow";
        }
        return -1;
    }
    write_u16(query + off, 1); /* A */
    write_u16(query + off + 2, 1); /* IN */
    off += 4;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (reason_out != NULL) {
            *reason_out = "socket_create_failed";
        }
        return -1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(BOOTSTRAP_DNS_PORT);
    dst.sin_addr = resolver_addr;

    if (sendto(fd, query, off, 0, (struct sockaddr *)&dst, sizeof(dst)) != (ssize_t)off) {
        close(fd);
        if (reason_out != NULL) {
            *reason_out = "sendto_failed";
        }
        return -1;
    }

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    int prc = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 1000);
    if (prc <= 0) {
        close(fd);
        if (reason_out != NULL) {
            *reason_out = (prc == 0) ? "poll_timeout" : "poll_failed";
        }
        return -1;
    }
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        close(fd);
        if (reason_out != NULL) {
            *reason_out = "poll_revents_error";
        }
        return -1;
    }

    uint8_t resp[1500];
    ssize_t n = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
    close(fd);
    if (n < 12) {
        if (reason_out != NULL) {
            *reason_out = "recv_short_or_failed";
        }
        return -1;
    }
    if (read_u16(resp + 0) != txid) {
        if (reason_out != NULL) {
            *reason_out = "txid_mismatch";
        }
        return -1;
    }

    return parse_recursive_a_answer(resp, (size_t)n, addr_be_out, ttl_out, reason_out);
}

int upstream_bootstrap_configure(upstream_client_t *client, const proxy_config_t *config) {
    if (client == NULL || config == NULL) {
        return -1;
    }

    client->bootstrap_resolver_count = 0;
    for (int i = 0; i < config->bootstrap_resolver_count && i < UPSTREAM_MAX_BOOTSTRAP_RESOLVERS; i++) {
        strncpy(client->bootstrap_resolvers[i], config->bootstrap_resolvers[i], sizeof(client->bootstrap_resolvers[i]) - 1);
        client->bootstrap_resolvers[i][sizeof(client->bootstrap_resolvers[i]) - 1] = '\0';
        client->bootstrap_resolver_count++;
    }

    return 0;
}

int upstream_bootstrap_try_stage2(upstream_client_t *client, upstream_server_t *server, int timeout_ms, const char **reason_out) {
    if (reason_out != NULL) {
        *reason_out = "stage2_failed";
    }
    if (client == NULL || server == NULL) {
        if (reason_out != NULL) {
            *reason_out = "invalid_input";
        }
        return -1;
    }

    uint64_t now = now_ms();
    if (server->stage.has_bootstrap_v4 && now < server->stage.bootstrap_expires_at_ms) {
        if (reason_out != NULL) {
            *reason_out = "cache_hit";
        }
        return 0;
    }

    if (server->stage.stage2_next_retry_ms != 0 && now < server->stage.stage2_next_retry_ms) {
        if (reason_out != NULL) {
            *reason_out = "cooldown";
        }
        return -1;
    }

    const char *last_reason = "no_bootstrap_resolvers";

    for (int i = 0; i < client->bootstrap_resolver_count; i++) {
        uint32_t addr_be = 0;
        uint32_t ttl = 0;
        const char *resolver_reason = NULL;
        if (stage2_query_resolver(client->bootstrap_resolvers[i], server->host, timeout_ms, &addr_be, &ttl, &resolver_reason) == 0) {
            uint64_t ttl_ms = ttl == 0 ? STAGE1_CACHE_TTL_MS : (uint64_t)ttl * 1000ULL;
            if (ttl_ms < STAGE2_CACHE_TTL_MIN_MS) {
                ttl_ms = STAGE2_CACHE_TTL_MIN_MS;
            }
            if (ttl_ms > STAGE2_CACHE_TTL_MAX_MS) {
                ttl_ms = STAGE2_CACHE_TTL_MAX_MS;
            }
            server->stage.bootstrap_addr_v4_be = addr_be;
            server->stage.has_bootstrap_v4 = 1;
            server->stage.bootstrap_expires_at_ms = now + ttl_ms;
            server->stage.stage2_next_retry_ms = 0;
            if (reason_out != NULL) {
                *reason_out = "ok";
            }
            return 0;
        }
        if (resolver_reason != NULL) {
            last_reason = resolver_reason;
        }
    }

    server->stage.stage2_next_retry_ms = now + STAGE2_RECURSIVE_RETRY_COOLDOWN_MS;
    if (reason_out != NULL) {
        *reason_out = last_reason;
    }

    return -1;
}

int upstream_bootstrap_stage1_hydrate(upstream_client_t *client, upstream_server_t *server, int timeout_ms) {
    if (client == NULL || server == NULL || !server->stage.has_stage1_cached_v4) {
        return -1;
    }

    uint64_t now = now_ms();
    for (int i = 0; i < client->bootstrap_resolver_count; i++) {
        uint32_t addr_be = 0;
        uint32_t ttl = 0;
        if (stage2_query_resolver(client->bootstrap_resolvers[i], server->host, timeout_ms, &addr_be, &ttl, NULL) == 0) {
            uint64_t ttl_ms = ttl == 0 ? STAGE1_CACHE_TTL_MS : (uint64_t)ttl * 1000ULL;
            if (ttl_ms < STAGE2_CACHE_TTL_MIN_MS) {
                ttl_ms = STAGE2_CACHE_TTL_MIN_MS;
            }
            if (ttl_ms > STAGE2_CACHE_TTL_MAX_MS) {
                ttl_ms = STAGE2_CACHE_TTL_MAX_MS;
            }

            server->stage.stage1_cached_addr_v4_be = addr_be;
            server->stage.has_stage1_cached_v4 = 1;
            server->stage.stage1_cache_expires_at_ms = now + ttl_ms;

            server->stage.bootstrap_addr_v4_be = addr_be;
            server->stage.has_bootstrap_v4 = 1;
            server->stage.bootstrap_expires_at_ms = now + ttl_ms;
            return 0;
        }
    }

    return -1;
}

int upstream_bootstrap_try_stage3(upstream_server_t *server, int timeout_ms, const char **reason_out) {
    if (reason_out != NULL) {
        *reason_out = "stage3_failed";
    }
    if (server == NULL) {
        if (reason_out != NULL) {
            *reason_out = "invalid_input";
        }
        return -1;
    }

    uint64_t now = now_ms();
    if (server->stage.iterative_last_attempt_ms != 0 &&
        now - server->stage.iterative_last_attempt_ms < UPSTREAM_STAGE3_RETRY_COOLDOWN_MS) {
        if (reason_out != NULL) {
            *reason_out = "cooldown";
        }
        return -1;
    }
    server->stage.iterative_last_attempt_ms = now;

    uint32_t addr_be = 0;
    if (iterative_resolve_a(server->host, timeout_ms, &addr_be) != PROXY_OK) {
        if (reason_out != NULL) {
            *reason_out = "iterative_resolve_failed";
        }
        return -1;
    }

    server->stage.bootstrap_addr_v4_be = addr_be;
    server->stage.has_bootstrap_v4 = 1;
    server->stage.bootstrap_expires_at_ms = now + STAGE1_CACHE_TTL_MS;
    if (reason_out != NULL) {
        *reason_out = "ok";
    }
    return 0;
}

upstream_stage1_cache_result_t upstream_bootstrap_stage1_prepare(upstream_server_t *server) {
    if (server == NULL) {
        return UPSTREAM_STAGE1_CACHE_MISS;
    }

    uint64_t now = now_ms();
    if (server->stage.has_stage1_cached_v4 && now < server->stage.stage1_cache_expires_at_ms) {
        return UPSTREAM_STAGE1_CACHE_HIT;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai;
    if (test_force_getaddrinfo_fail()) {
        gai = EAI_FAIL;
    } else {
        gai = getaddrinfo(server->host, NULL, &hints, &res);
    }
    if (gai != 0 || res == NULL) {
        server->stage.has_stage1_cached_v4 = 0;
        return UPSTREAM_STAGE1_CACHE_MISS;
    }

    /* Copy the resolved address through a properly-aligned local rather than
     * casting from struct sockaddr * to struct sockaddr_in *. The cast
     * increases required alignment (2 -> 4) which is a portability hazard
     * on strict-alignment platforms even though glibc happens to align the
     * getaddrinfo result correctly. */
    struct sockaddr_in sin;
    memcpy(&sin, res->ai_addr, sizeof(sin));
    server->stage.stage1_cached_addr_v4_be = sin.sin_addr.s_addr;
    server->stage.has_stage1_cached_v4 = 1;
    server->stage.stage1_cache_expires_at_ms = now + STAGE1_CACHE_TTL_MS;
    freeaddrinfo(res);
    return UPSTREAM_STAGE1_CACHE_REFRESHED;
}

void upstream_bootstrap_stage1_invalidate(upstream_server_t *server) {
    if (server == NULL) {
        return;
    }
    server->stage.has_stage1_cached_v4 = 0;
    server->stage.stage1_cache_expires_at_ms = 0;
    server->stage.stage1_cached_failures = 0;
}
