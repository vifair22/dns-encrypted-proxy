#include "dns_server.h"

#include "dns_message.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
} tcp_client_ctx_t;

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

static int build_servfail_response(const uint8_t *query, size_t query_len, uint8_t **response_out, size_t *response_len_out) {
    if (query_len < 12 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    size_t question_len = 0;
    if (dns_question_section_length(query, query_len, &question_len) != 0) {
        return -1;
    }

    size_t response_len = 12 + question_len;
    uint8_t *response = calloc(1, response_len);
    if (response == NULL) {
        return -1;
    }

    response[0] = query[0];
    response[1] = query[1];

    uint16_t query_flags = read_u16(query + 2);
    uint16_t response_flags = (uint16_t)(0x8000u | (query_flags & 0x0100u) | 0x0080u | 0x0002u);
    write_u16(response + 2, response_flags);

    uint16_t qdcount = read_u16(query + 4);
    write_u16(response + 4, qdcount);

    if (question_len > 0) {
        memcpy(response + 12, query + 12, question_len);
    }

    *response_out = response;
    *response_len_out = response_len;
    return 0;
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
            size_t rr_end = 0;
            if (dns_rr_end_offset(response, response_len, offset, &rr_end) != 0) {
                malformed = 1;
                break;
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
    if (!is_truncated && !malformed) {
        return -1;
    }
    if (malformed) {
        include_end = 12;
        include_qd = 0;
        include_an = 0;
        include_ns = 0;
        include_ar = 0;
    }

    uint8_t *truncated = malloc(include_end);
    if (truncated == NULL) {
        return -1;
    }

    memcpy(truncated, response, include_end);

    uint16_t flags = read_u16(truncated + 2);
    flags = (uint16_t)(flags | 0x0200u); /* TC */
    write_u16(truncated + 2, flags);

    write_u16(truncated + 4, include_qd);
    write_u16(truncated + 6, include_an);
    write_u16(truncated + 8, include_ns);
    write_u16(truncated + 10, include_ar);

    *truncated_out = truncated;
    *truncated_len_out = include_end;
    return 0;
}

static int process_query(proxy_server_t *server, const uint8_t *query, size_t query_len, uint8_t **response_out, size_t *response_len_out) {
    if (server == NULL || query == NULL || query_len < 12 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    uint8_t key[CACHE_KEY_MAX_SIZE];
    size_t key_len = 0;
    int key_ok = (dns_extract_question_key(query, query_len, key, sizeof(key), &key_len) == 0);

    const uint8_t request_id[2] = {query[0], query[1]};

    if (key_ok) {
        if (dns_cache_lookup(&server->cache, key, key_len, request_id, response_out, response_len_out)) {
            return 0;
        }
    }

    const char *used_url = NULL;
    if (doh_client_resolve(&server->doh_client, query, query_len, response_out, response_len_out, &used_url) == 0) {
        if (*response_len_out >= 2) {
            (*response_out)[0] = query[0];
            (*response_out)[1] = query[1];
        }

        int ttl_ok = 0;
        uint32_t min_ttl = dns_response_min_ttl(*response_out, *response_len_out, &ttl_ok);
        if (key_ok && ttl_ok && min_ttl > 0) {
            dns_cache_store(&server->cache, key, key_len, *response_out, *response_len_out, min_ttl);
        }

        if (used_url != NULL) {
            (void)used_url;
        }

        return 0;
    }

    return build_servfail_response(query, query_len, response_out, response_len_out);
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

    uint8_t buffer[DNS_MAX_MESSAGE_SIZE];

    while (!should_stop(server)) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLIN;

        int poll_rc = poll(&pfd, 1, 500);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (poll_rc == 0) {
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            break;
        }
        if ((pfd.revents & POLLIN) == 0) {
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t n = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);
        if (n <= 0) {
            continue;
        }

        uint8_t *response = NULL;
        size_t response_len = 0;
        if (process_query(server, buffer, (size_t)n, &response, &response_len) != 0) {
            continue;
        }

        if (response != NULL && response_len > 0) {
            size_t udp_limit = dns_udp_payload_limit_for_query(buffer, (size_t)n);
            if (response_len > udp_limit) {
                uint8_t *truncated = NULL;
                size_t truncated_len = 0;
                if (build_truncated_udp_response(response, response_len, udp_limit, &truncated, &truncated_len) == 0) {
                    free(response);
                    response = truncated;
                    response_len = truncated_len;
                } else {
                    free(response);
                    response = NULL;
                    response_len = 0;
                    if (build_servfail_response(buffer, (size_t)n, &response, &response_len) != 0) {
                        continue;
                    }
                }
            }

            sendto(fd, response, response_len, 0, (struct sockaddr *)&client_addr, client_len);
            free(response);
        }
    }

    return NULL;
}

static int recv_all(int fd, uint8_t *buffer, size_t len) {
    size_t offset = 0;
    while (offset < len) {
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

    while (!should_stop(server)) {
        uint8_t length_prefix[2];
        int rc = recv_all(client_fd, length_prefix, sizeof(length_prefix));
        if (rc <= 0) {
            break;
        }

        uint16_t message_len = read_u16(length_prefix);
        if (message_len == 0) {
            continue;
        }

        uint8_t *query = malloc(message_len);
        if (query == NULL) {
            break;
        }

        rc = recv_all(client_fd, query, message_len);
        if (rc <= 0) {
            free(query);
            break;
        }

        uint8_t *response = NULL;
        size_t response_len = 0;
        if (process_query(server, query, message_len, &response, &response_len) != 0) {
            free(query);
            break;
        }

        free(query);

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

        free(response);
    }

    close(client_fd);
    free(ctx);
    return NULL;
}

static void *tcp_accept_loop(void *arg) {
    socket_loop_ctx_t *ctx = (socket_loop_ctx_t *)arg;
    proxy_server_t *server = ctx->server;
    int fd = ctx->fd;

    while (!should_stop(server)) {
        struct pollfd pfd = {0};
        pfd.fd = fd;
        pfd.events = POLLIN;

        int poll_rc = poll(&pfd, 1, 500);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (poll_rc == 0) {
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            break;
        }
        if ((pfd.revents & POLLIN) == 0) {
            continue;
        }

        int client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            continue;
        }

        tcp_client_ctx_t *client_ctx = calloc(1, sizeof(*client_ctx));
        if (client_ctx == NULL) {
            close(client_fd);
            continue;
        }

        client_ctx->server = server;
        client_ctx->client_fd = client_fd;

        pthread_t thread;
        if (pthread_create(&thread, NULL, tcp_client_loop, client_ctx) != 0) {
            close(client_fd);
            free(client_ctx);
            continue;
        }
        pthread_detach(thread);
    }

    return NULL;
}

int proxy_server_run(proxy_server_t *server) {
    if (server == NULL) {
        return -1;
    }

    int udp_fd = create_udp_socket(&server->config);
    if (udp_fd < 0) {
        fprintf(stderr, "Failed to create/bind UDP socket on %s:%d\n", server->config.listen_addr, server->config.listen_port);
        return -1;
    }

    int tcp_fd = create_tcp_socket(&server->config);
    if (tcp_fd < 0) {
        fprintf(stderr, "Failed to create/bind TCP socket on %s:%d\n", server->config.listen_addr, server->config.listen_port);
        close(udp_fd);
        return -1;
    }

    socket_loop_ctx_t udp_ctx = {.server = server, .fd = udp_fd};
    socket_loop_ctx_t tcp_ctx = {.server = server, .fd = tcp_fd};

    pthread_t udp_thread;
    pthread_t tcp_thread;

    if (pthread_create(&udp_thread, NULL, udp_loop, &udp_ctx) != 0) {
        close(udp_fd);
        close(tcp_fd);
        return -1;
    }

    if (pthread_create(&tcp_thread, NULL, tcp_accept_loop, &tcp_ctx) != 0) {
        close(udp_fd);
        close(tcp_fd);
        pthread_join(udp_thread, NULL);
        return -1;
    }

    pthread_join(udp_thread, NULL);
    pthread_join(tcp_thread, NULL);

    close(udp_fd);
    close(tcp_fd);

    return 0;
}
