#define _POSIX_C_SOURCE 200809L

#include "upstream.h"
#include "upstream_dot.h"
#include "dns_message.h"
#include "logger.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * DoT client implementation
 * 
 * Uses OpenSSL for DNS-over-TLS queries.
 * Maintains a connection pool with TLS sessions.
 */

#define DOT_MAX_MESSAGE_SIZE 65535

typedef struct {
    int fd;
    SSL *ssl;
    int in_use;
    char host[256];
    int port;
} dot_connection_t;

struct upstream_dot_client {
    SSL_CTX *ssl_ctx;
    dot_connection_t *pool;
    int pool_size;
    pthread_mutex_t pool_mutex;
    pthread_cond_t pool_cond;
    int initialized;
};

static uint16_t read_u16(const uint8_t *ptr) {
    return (uint16_t)((ptr[0] << 8) | ptr[1]);
}

static void write_u16(uint8_t *ptr, uint16_t value) {
    ptr[0] = (uint8_t)((value >> 8) & 0xFFu);
    ptr[1] = (uint8_t)(value & 0xFFu);
}

static void format_ipv4(uint32_t addr_v4_be, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    struct in_addr addr;
    addr.s_addr = addr_v4_be;
    if (inet_ntop(AF_INET, &addr, out, (socklen_t)out_len) == NULL) {
        out[0] = '\0';
    }
}

static const char *dot_normalize_reason(const char *detail_reason) {
    if (detail_reason == NULL) {
        return "unknown";
    }
    if (strcmp(detail_reason, "connect_failed") == 0) {
        return "transport_connect_failed";
    }
    if (strcmp(detail_reason, "tls_handshake_failed") == 0 || strcmp(detail_reason, "ssl_new_failed") == 0) {
        return "tls_handshake_failed";
    }
    return detail_reason;
}

static void log_dot_attempt_failure_impl(
    const char *caller_func,
    const upstream_server_t *server,
    const char *phase,
    const char *detail_reason,
    int used_override_v4,
    uint32_t override_addr_v4_be,
    int timeout_ms) {
    char ip_text[INET_ADDRSTRLEN];
    ip_text[0] = '\0';
    if (used_override_v4) {
        format_ipv4(override_addr_v4_be, ip_text, sizeof(ip_text));
    }
    const char *reason = dot_normalize_reason(detail_reason);
    logger_logf(
        caller_func,
        "WARN",
        "DoT %s failed: host=%s reason=%s timeout_ms=%d override_ip=%s detail=%s",
        phase,
        server->host,
        reason,
        timeout_ms,
        used_override_v4 ? ip_text : "none",
        detail_reason != NULL ? detail_reason : "none");
}

#define LOG_DOT_ATTEMPT_FAILURE(server, phase, detail_reason, used_override_v4, override_addr_v4_be, timeout_ms) \
    log_dot_attempt_failure_impl(__func__, server, phase, detail_reason, used_override_v4, override_addr_v4_be, timeout_ms)

static int test_force_getaddrinfo_fail(void) {
    const char *v = getenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_GETADDRINFO_FAIL");
    return v != NULL && *v != '\0';
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int connect_with_timeout(const char *host, int port, int timeout_ms) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    struct addrinfo *res = NULL;
    if (test_force_getaddrinfo_fail() || getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    
    if (set_nonblocking(fd) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    /* Non-blocking connect + poll keeps timeout deterministic per attempt. */
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    
    if (rc == 0) {
        return fd;
    }
    
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    
    /* Wait for connection with timeout */
    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    
    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        close(fd);
        return -1;
    }
    
    /* Check for connection error */
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
        close(fd);
        return -1;
    }
    
    return fd;
}

static int connect_ipv4_with_timeout(uint32_t addr_v4_be, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = addr_v4_be;
    addr.sin_port = htons((uint16_t)port);

    int rc = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) {
        close(fd);
        return -1;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void close_connection(dot_connection_t *conn) {
    if (conn == NULL) {
        return;
    }
    
    if (conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    
    conn->host[0] = '\0';
    conn->port = 0;
}

static int establish_tls_connection(
    upstream_dot_client_t *client,
    dot_connection_t *conn,
    const char *host,
    int port,
    int timeout_ms,
    int use_bootstrap_v4,
    uint32_t bootstrap_addr_v4_be,
    const char **reason_out) {
    if (conn == NULL || client == NULL || host == NULL) {
        if (reason_out != NULL) {
            *reason_out = "invalid_arguments";
        }
        return -1;
    }
    if (reason_out != NULL) {
        *reason_out = "connect_failed";
    }

    /* Close existing connection if any */
    close_connection(conn);
    
    /* Connect TCP */
    if (use_bootstrap_v4) {
        conn->fd = connect_ipv4_with_timeout(bootstrap_addr_v4_be, port, timeout_ms);
    } else {
        conn->fd = connect_with_timeout(host, port, timeout_ms);
    }
    if (conn->fd < 0) {
        return -1;
    }
    
    /*
     * SSL I/O below uses poll-driven helpers, so we keep SSL itself in
     * blocking mode to simplify OpenSSL error handling and avoid WANT_READ/
     * WANT_WRITE state machinery.
     */
    int flags = fcntl(conn->fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(conn->fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    
    /* Create SSL connection */
    conn->ssl = SSL_new(client->ssl_ctx);
    if (conn->ssl == NULL) {
        if (reason_out != NULL) {
            *reason_out = "ssl_new_failed";
        }
        close(conn->fd);
        conn->fd = -1;
        return -1;
    }
    
    /* Set SNI hostname */
    SSL_set_tlsext_host_name(conn->ssl, host);
    
    /* Set hostname for verification */
    SSL_set1_host(conn->ssl, host);
    
    SSL_set_fd(conn->ssl, conn->fd);
    
    /* Perform TLS handshake */
    int rc = SSL_connect(conn->ssl);
    if (rc != 1) {
        if (reason_out != NULL) {
            *reason_out = "tls_handshake_failed";
        }
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        close(conn->fd);
        conn->fd = -1;
        return -1;
    }
    
    /* Store connection info */
    strncpy(conn->host, host, sizeof(conn->host) - 1);
    conn->host[sizeof(conn->host) - 1] = '\0';
    conn->port = port;
    
    return 0;
}

static int pool_acquire(upstream_dot_client_t *client, dot_connection_t **conn_out, int *slot_out) {
    /* Bounded pool with wait keeps TLS connection reuse stable under bursts. */
    pthread_mutex_lock(&client->pool_mutex);

    for (;;) {
        for (int i = 0; i < client->pool_size; i++) {
            if (!client->pool[i].in_use) {
                client->pool[i].in_use = 1;
                *conn_out = &client->pool[i];
                *slot_out = i;
                pthread_mutex_unlock(&client->pool_mutex);
                return 0;
            }
        }

        pthread_cond_wait(&client->pool_cond, &client->pool_mutex);
    }
}

static void pool_release(upstream_dot_client_t *client, int slot) {
    pthread_mutex_lock(&client->pool_mutex);
    client->pool[slot].in_use = 0;
    pthread_cond_signal(&client->pool_cond);
    pthread_mutex_unlock(&client->pool_mutex);
}

static int ssl_read_all(SSL *ssl, uint8_t *buffer, size_t len, int timeout_ms) {
    size_t offset = 0;
    int fd = SSL_get_fd(ssl);
    
    while (offset < len) {
        /* Poll before SSL_read so stalled upstreams respect our timeout SLA. */
        if (timeout_ms > 0) {
            struct pollfd pfd = {0};
            pfd.fd = fd;
            pfd.events = POLLIN;
            
            int rc = poll(&pfd, 1, timeout_ms);
            if (rc <= 0) {
                return -1;
            }
            if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return -1;
            }
        }
        
        int n = SSL_read(ssl, buffer + offset, (int)(len - offset));
        if (n <= 0) {
            return -1;
        }
        offset += (size_t)n;
    }
    
    return 0;
}

static int ssl_write_all(SSL *ssl, const uint8_t *buffer, size_t len) {
    size_t offset = 0;
    
    while (offset < len) {
        int n = SSL_write(ssl, buffer + offset, (int)(len - offset));
        if (n <= 0) {
            return -1;
        }
        offset += (size_t)n;
    }
    
    return 0;
}

int upstream_dot_client_init(upstream_dot_client_t **client_out, const upstream_config_t *config) {
    if (client_out == NULL || config == NULL) {
        return -1;
    }
    
    upstream_dot_client_t *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return -1;
    }
    
    client->pool_size = config->pool_size > 0 ? config->pool_size : 4;
    
    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    /* Create SSL context */
    client->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (client->ssl_ctx == NULL) {
        free(client);
        return -1;
    }
    
    /* Set minimum TLS version to 1.2 */
    SSL_CTX_set_min_proto_version(client->ssl_ctx, TLS1_2_VERSION);
    
    /* Enable certificate verification */
    SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_PEER, NULL);
    
    /* Load system CA certificates */
    if (SSL_CTX_set_default_verify_paths(client->ssl_ctx) != 1) {
        SSL_CTX_free(client->ssl_ctx);
        free(client);
        return -1;
    }
    
    if (pthread_mutex_init(&client->pool_mutex, NULL) != 0) {
        SSL_CTX_free(client->ssl_ctx);
        free(client);
        return -1;
    }

    if (pthread_cond_init(&client->pool_cond, NULL) != 0) {
        pthread_mutex_destroy(&client->pool_mutex);
        SSL_CTX_free(client->ssl_ctx);
        free(client);
        return -1;
    }
    
    client->pool = calloc((size_t)client->pool_size, sizeof(*client->pool));
    if (client->pool == NULL) {
        pthread_cond_destroy(&client->pool_cond);
        pthread_mutex_destroy(&client->pool_mutex);
        SSL_CTX_free(client->ssl_ctx);
        free(client);
        return -1;
    }
    
    for (int i = 0; i < client->pool_size; i++) {
        client->pool[i].fd = -1;
        client->pool[i].ssl = NULL;
        client->pool[i].in_use = 0;
    }
    
    client->initialized = 1;
    *client_out = client;
    return 0;
}

void upstream_dot_client_destroy(upstream_dot_client_t *client) {
    if (client == NULL) {
        return;
    }

    if (client->pool != NULL) {
        for (int i = 0; i < client->pool_size; i++) {
            close_connection(&client->pool[i]);
        }
        free(client->pool);
    }

    if (client->initialized) {
        pthread_cond_destroy(&client->pool_cond);
        pthread_mutex_destroy(&client->pool_mutex);
    }
    
    if (client->ssl_ctx != NULL) {
        SSL_CTX_free(client->ssl_ctx);
    }
    
    free(client);
}

int upstream_dot_resolve(
    upstream_dot_client_t *client,
    upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    
    if (client == NULL || server == NULL || query == NULL || query_len == 0 ||
        response_out == NULL || response_len_out == NULL) {
        return -1;
    }
    
    if (server->type != UPSTREAM_TYPE_DOT) {
        return -1;
    }
    
    if (query_len > DOT_MAX_MESSAGE_SIZE - 2) {
        return -1;
    }
    
    *response_out = NULL;
    *response_len_out = 0;
    
    dot_connection_t *conn = NULL;
    int slot = -1;
    if (pool_acquire(client, &conn, &slot) != 0) {
        return -1;
    }
    
    /* Check if we need to establish/re-establish connection */
    int need_connect = 0;
    if (conn->ssl == NULL || conn->fd < 0) {
        need_connect = 1;
    } else if (strcmp(conn->host, server->host) != 0 || conn->port != server->port) {
        /* Different server, need new connection */
        need_connect = 1;
    }
    
    if (need_connect) {
        int connected = 0;
        int stage2_used = 0;
        const char *attempt_reason = NULL;

        if (server->stage.has_stage1_cached_v4 &&
            establish_tls_connection(
                client,
                conn,
                server->host,
                server->port,
                timeout_ms,
                1,
                server->stage.stage1_cached_addr_v4_be,
                &attempt_reason)
                == 0) {
            connected = 1;
        } else if (server->stage.has_stage1_cached_v4) {
            LOG_DOT_ATTEMPT_FAILURE(
                server,
                "stage1 cached IPv4",
                attempt_reason,
                1,
                server->stage.stage1_cached_addr_v4_be,
                timeout_ms);
        }

        if (!connected && establish_tls_connection(client, conn, server->host, server->port, timeout_ms, 0, 0, &attempt_reason) == 0) {
            connected = 1;
        } else if (!connected) {
            LOG_DOT_ATTEMPT_FAILURE(server, "primary request", attempt_reason, 0, 0, timeout_ms);
        }

        if (!connected) {
            /*
             * Stage-2 fallback: connect socket to pinned IPv4 only for dial,
             * but keep TLS hostname checks against server->host for security.
             */
            LOGF_WARN("DoT stage1 local resolver failed, trying stage2 bootstrap IPv4: host=%s", server->host);
            if (!server->stage.has_bootstrap_v4 ||
                establish_tls_connection(
                    client,
                    conn,
                    server->host,
                    server->port,
                    timeout_ms,
                    1,
                    server->stage.bootstrap_addr_v4_be,
                    &attempt_reason)
                    == 0) {
                connected = 1;
                stage2_used = 1;
            } else {
                if (server->stage.has_bootstrap_v4) {
                    LOG_DOT_ATTEMPT_FAILURE(
                        server,
                        "stage2 bootstrap IPv4",
                        attempt_reason,
                        1,
                        server->stage.bootstrap_addr_v4_be,
                        timeout_ms);
                }
                pool_release(client, slot);
                return -1;
            }
        }

        if (stage2_used) {
            LOGF_INFO("DoT stage2 bootstrap IPv4 succeeded: host=%s", server->host);
        }
    }
    
    /* Send DNS query with 2-byte length prefix (RFC 7858) */
    uint8_t length_prefix[2];
    write_u16(length_prefix, (uint16_t)query_len);
    
    if (ssl_write_all(conn->ssl, length_prefix, 2) != 0 ||
        ssl_write_all(conn->ssl, query, query_len) != 0) {
        close_connection(conn);
        pool_release(client, slot);
        return -1;
    }
    
    /* Read response length */
    uint8_t response_length[2];
    if (ssl_read_all(conn->ssl, response_length, 2, timeout_ms) != 0) {
        close_connection(conn);
        pool_release(client, slot);
        return -1;
    }
    
    uint16_t response_len = read_u16(response_length);
    if (response_len == 0) {
        close_connection(conn);
        pool_release(client, slot);
        return -1;
    }
    
    /* Read response */
    uint8_t *response = malloc(response_len);
    if (response == NULL) {
        close_connection(conn);
        pool_release(client, slot);
        return -1;
    }
    
    if (ssl_read_all(conn->ssl, response, response_len, timeout_ms) != 0) {
        free(response);
        close_connection(conn);
        pool_release(client, slot);
        return -1;
    }
    
    pool_release(client, slot);
    
    /* Validate response matches query */
    if (dns_validate_response_for_query(query, query_len, response, response_len) != 0) {
        free(response);
        return -1;
    }
    
    *response_out = response;
    *response_len_out = response_len;
    return 0;
}

int upstream_dot_client_get_pool_stats(
    upstream_dot_client_t *client,
    int *capacity_out,
    int *in_use_out,
    int *alive_out) {
    if (capacity_out != NULL) {
        *capacity_out = 0;
    }
    if (in_use_out != NULL) {
        *in_use_out = 0;
    }
    if (alive_out != NULL) {
        *alive_out = 0;
    }

    if (client == NULL) {
        return -1;
    }

    int in_use = 0;
    int alive = 0;

    pthread_mutex_lock(&client->pool_mutex);
    for (int i = 0; i < client->pool_size; i++) {
        if (client->pool[i].in_use) {
            in_use++;
        }
        if (client->pool[i].fd >= 0 && client->pool[i].ssl != NULL) {
            alive++;
        }
    }
    pthread_mutex_unlock(&client->pool_mutex);

    if (capacity_out != NULL) {
        *capacity_out = client->pool_size;
    }
    if (in_use_out != NULL) {
        *in_use_out = in_use;
    }
    if (alive_out != NULL) {
        *alive_out = alive;
    }

    return 0;
}
