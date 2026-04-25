/*
 * Integration tests for dns-encrypted-proxy
 * 
 * These tests verify end-to-end behavior including:
 * - Cache flow (store from upstream, serve from cache)
 * - DNS message processing pipeline
 * - Configuration integration
 */
#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cache.h"
#include "config.h"
#include "dns_server.h"
#include "dns_message.h"
#include "metrics.h"
#include "upstream.h"
#include "test_helpers.h"
#include "test_fixtures.h"

static int upstream_resolve(
    upstream_client_t *client,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (client == NULL || query == NULL || query_len == 0 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }
    for (int i = 0; i < client->server_count; i++) {
        if (upstream_resolve_on_server(client, i, query, query_len, response_out, response_len_out) == 0) {
            return 0;
        }
    }
    return -1;
}

typedef enum {
    MOCK_TLS_MODE_DOH,
    MOCK_TLS_MODE_DOT
} mock_tls_mode_t;

typedef struct {
    mock_tls_mode_t mode;
    const uint8_t *expected_query;
    size_t expected_query_len;
    const uint8_t *response;
    size_t response_len;
    const char *cert_path;
    const char *key_path;

    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready;
    int done;
    int port;
    int result;

    int dot_close_before_length;
    size_t dot_partial_response_bytes;
} mock_tls_server_t;

static int ssl_write_all(SSL *ssl, const uint8_t *data, size_t len) {
    size_t written = 0;
    while (written < len) {
        int n = SSL_write(ssl, data + written, (int)(len - written));
        if (n <= 0) {
            return -1;
        }
        written += (size_t)n;
    }
    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *data, size_t len) {
    size_t read_total = 0;
    while (read_total < len) {
        int n = SSL_read(ssl, data + read_total, (int)(len - read_total));
        if (n <= 0) {
            return -1;
        }
        read_total += (size_t)n;
    }
    return 0;
}

static int mock_handle_doh(SSL *ssl, const mock_tls_server_t *server) {
    uint8_t request_buf[2048];
    int n = SSL_read(ssl, request_buf, (int)sizeof(request_buf));
    if (n <= 0) {
        return -1;
    }

    char response_headers[256];
    int hdr_len = snprintf(
        response_headers,
        sizeof(response_headers),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        server->response_len);
    if (hdr_len <= 0 || (size_t)hdr_len >= sizeof(response_headers)) {
        return -1;
    }

    if (ssl_write_all(ssl, (const uint8_t *)response_headers, (size_t)hdr_len) != 0) {
        return -1;
    }
    if (ssl_write_all(ssl, server->response, server->response_len) != 0) {
        return -1;
    }

    return 0;
}

static int mock_handle_dot(SSL *ssl, const mock_tls_server_t *server) {
    uint8_t len_bytes[2];
    if (ssl_read_all(ssl, len_bytes, sizeof(len_bytes)) != 0) {
        return -1;
    }

    uint16_t qlen = (uint16_t)(((uint16_t)len_bytes[0] << 8) | (uint16_t)len_bytes[1]);
    if ((size_t)qlen != server->expected_query_len) {
        return -1;
    }

    uint8_t *query = malloc(qlen);
    if (query == NULL) {
        return -1;
    }
    int result = 0;

    if (ssl_read_all(ssl, query, qlen) != 0) {
        result = -1;
        goto done;
    }
    if (memcmp(query, server->expected_query, qlen) != 0) {
        result = -1;
        goto done;
    }

    if (server->dot_close_before_length) {
        result = 0;
        goto done;
    }

    if (server->response_len > 65535) {
        result = -1;
        goto done;
    }

    uint8_t resp_len[2];
    resp_len[0] = (uint8_t)((server->response_len >> 8) & 0xFFu);
    resp_len[1] = (uint8_t)(server->response_len & 0xFFu);

    if (ssl_write_all(ssl, resp_len, sizeof(resp_len)) != 0) {
        result = -1;
        goto done;
    }

    if (server->dot_partial_response_bytes > 0 && server->dot_partial_response_bytes < server->response_len) {
        if (ssl_write_all(ssl, server->response, server->dot_partial_response_bytes) != 0) {
            result = -1;
        }
        goto done;
    }

    if (ssl_write_all(ssl, server->response, server->response_len) != 0) {
        result = -1;
    }

done:
    free(query);
    return result;
}

static void *mock_tls_server_thread(void *arg) {
    mock_tls_server_t *server = (mock_tls_server_t *)arg;
    int result = -1;
    SSL_CTX *ctx = NULL;
    int listen_fd = -1;
    int client_fd = -1;
    SSL *ssl = NULL;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        goto done;
    }
    if (SSL_CTX_use_certificate_file(ctx, server->cert_path, SSL_FILETYPE_PEM) != 1) {
        goto done;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, server->key_path, SSL_FILETYPE_PEM) != 1) {
        goto done;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        goto done;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        goto done;
    }
    if (listen(listen_fd, 1) != 0) {
        goto done;
    }

    socklen_t addr_len = sizeof(addr);
    if (getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        goto done;
    }

    pthread_mutex_lock(&server->mutex);
    server->port = ntohs(addr.sin_port);
    server->ready = 1;
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);

    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        goto done;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto done;
    }
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) != 1) {
        goto done;
    }

    if (server->mode == MOCK_TLS_MODE_DOH) {
        result = mock_handle_doh(ssl, server);
    } else {
        result = mock_handle_dot(ssl, server);
    }

done:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (client_fd >= 0) {
        close(client_fd);
    }
    if (listen_fd >= 0) {
        close(listen_fd);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }

    pthread_mutex_lock(&server->mutex);
    server->result = result;
    server->done = 1;
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);
    return NULL;
}

static int mock_tls_server_start(mock_tls_server_t *server, mock_tls_mode_t mode, const char *cert_path, const char *key_path) {
    memset(server, 0, sizeof(*server));
    server->mode = mode;
    server->expected_query = DNS_QUERY_WWW_EXAMPLE_COM_A;
    server->expected_query_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    server->response = DNS_RESPONSE_WWW_EXAMPLE_COM_A;
    server->response_len = DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN;
    server->cert_path = cert_path;
    server->key_path = key_path;
    server->result = -1;

    if (pthread_mutex_init(&server->mutex, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&server->cond, NULL) != 0) {
        pthread_mutex_destroy(&server->mutex);
        return -1;
    }

    if (pthread_create(&server->thread, NULL, mock_tls_server_thread, server) != 0) {
        pthread_cond_destroy(&server->cond);
        pthread_mutex_destroy(&server->mutex);
        return -1;
    }

    pthread_mutex_lock(&server->mutex);
    while (!server->ready) {
        pthread_cond_wait(&server->cond, &server->mutex);
    }
    pthread_mutex_unlock(&server->mutex);
    return 0;
}

static void mock_tls_server_join_and_destroy(mock_tls_server_t *server) {
    if (server == NULL) {
        return;
    }
    pthread_join(server->thread, NULL);
    pthread_cond_destroy(&server->cond);
    pthread_mutex_destroy(&server->mutex);
}

static int resolve_test_cert_paths(char *cert_out, size_t cert_out_len, char *key_out, size_t key_out_len) {
    /* Test cwd depends on which build tree ctest invoked us from:
     *   repo root             -> tests/certs/...
     *   build/<variant>/      -> ../../tests/certs/...
     *   build/matrix/<combo>/ -> ../../../tests/certs/... */
    const char *cert_candidates[] = {
        "tests/certs/localhost.cert.pem",
        "../tests/certs/localhost.cert.pem",
        "../../tests/certs/localhost.cert.pem",
        "../../../tests/certs/localhost.cert.pem"
    };
    const char *key_candidates[] = {
        "tests/certs/localhost.key.pem",
        "../tests/certs/localhost.key.pem",
        "../../tests/certs/localhost.key.pem",
        "../../../tests/certs/localhost.key.pem"
    };

    int cert_found = 0;
    int key_found = 0;

    for (size_t i = 0; i < sizeof(cert_candidates) / sizeof(cert_candidates[0]); i++) {
        if (access(cert_candidates[i], R_OK) == 0) {
            strncpy(cert_out, cert_candidates[i], cert_out_len - 1);
            cert_out[cert_out_len - 1] = '\0';
            cert_found = 1;
            break;
        }
    }

    for (size_t i = 0; i < sizeof(key_candidates) / sizeof(key_candidates[0]); i++) {
        if (access(key_candidates[i], R_OK) == 0) {
            strncpy(key_out, key_candidates[i], key_out_len - 1);
            key_out[key_out_len - 1] = '\0';
            key_found = 1;
            break;
        }
    }

    return (cert_found && key_found) ? 0 : -1;
}

static int reserve_unused_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }

    int port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static int http_get_local(int port, const char *path, char *buf, size_t buf_size) {
    if (path == NULL || buf == NULL || buf_size == 0) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    char req[256];
    int req_len = snprintf(
        req,
        sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n\r\n",
        path);
    if (req_len <= 0 || (size_t)req_len >= sizeof(req)) {
        close(fd);
        return -1;
    }

    if (send(fd, req, (size_t)req_len, 0) != req_len) {
        close(fd);
        return -1;
    }

    size_t off = 0;
    while (off + 1 < buf_size) {
        ssize_t n = recv(fd, buf + off, buf_size - off - 1, 0);
        if (n <= 0) {
            break;
        }
        off += (size_t)n;
    }

    buf[off] = '\0';
    close(fd);
    return (off > 0) ? 0 : -1;
}

typedef struct {
    proxy_server_t *server;
    int rc;
} proxy_thread_ctx_t;

static void *proxy_server_thread_main(void *arg) {
    proxy_thread_ctx_t *ctx = (proxy_thread_ctx_t *)arg;
    if (ctx == NULL || ctx->server == NULL) {
        return NULL;
    }
    ctx->rc = proxy_server_run(ctx->server);
    return NULL;
}

static int send_udp_query_and_recv(int port, const uint8_t *query, size_t query_len, uint8_t *resp_out, size_t *resp_len_out) {
    if (query == NULL || query_len == 0 || resp_out == NULL || resp_len_out == NULL) {
        return -1;
    }

    *resp_len_out = 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (sendto(fd, query, query_len, 0, (struct sockaddr *)&addr, sizeof(addr)) != (ssize_t)query_len) {
        close(fd);
        return -1;
    }

    ssize_t n = recvfrom(fd, resp_out, 1500, 0, NULL, NULL);
    close(fd);
    if (n <= 0) {
        return -1;
    }

    *resp_len_out = (size_t)n;
    return 0;
}

static int open_tcp_connection_local(int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    const int max_attempts = 100;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            return fd;
        }

        close(fd);

        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    return -1;
}

static int send_tcp_query_and_recv(int port, const uint8_t *query, size_t query_len, uint8_t *resp_out, size_t *resp_len_out) {
    if (query == NULL || query_len == 0 || query_len > UINT16_MAX || resp_out == NULL || resp_len_out == NULL) {
        return -1;
    }

    *resp_len_out = 0;
    int fd = open_tcp_connection_local(port);
    if (fd < 0) {
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t len_prefix[2];
    len_prefix[0] = (uint8_t)((query_len >> 8) & 0xFFu);
    len_prefix[1] = (uint8_t)(query_len & 0xFFu);

    if (send(fd, len_prefix, sizeof(len_prefix), 0) != (ssize_t)sizeof(len_prefix) ||
        send(fd, query, query_len, 0) != (ssize_t)query_len) {
        close(fd);
        return -1;
    }

    uint8_t out_len[2];
    ssize_t n = recv(fd, out_len, sizeof(out_len), MSG_WAITALL);
    if (n != (ssize_t)sizeof(out_len)) {
        close(fd);
        return -1;
    }

    size_t resp_len = (size_t)(((uint16_t)out_len[0] << 8) | (uint16_t)out_len[1]);
    if (resp_len == 0 || resp_len > 1500) {
        close(fd);
        return -1;
    }

    n = recv(fd, resp_out, resp_len, MSG_WAITALL);
    close(fd);
    if (n != (ssize_t)resp_len) {
        return -1;
    }

    *resp_len_out = resp_len;
    return 0;
}

static int send_tcp_query_on_fd(int fd, const uint8_t *query, size_t query_len, uint8_t *resp_out, size_t *resp_len_out) {
    if (fd < 0 || query == NULL || query_len == 0 || query_len > UINT16_MAX || resp_out == NULL || resp_len_out == NULL) {
        return -1;
    }

    *resp_len_out = 0;

    uint8_t len_prefix[2];
    len_prefix[0] = (uint8_t)((query_len >> 8) & 0xFFu);
    len_prefix[1] = (uint8_t)(query_len & 0xFFu);

    if (send(fd, len_prefix, sizeof(len_prefix), 0) != (ssize_t)sizeof(len_prefix) ||
        send(fd, query, query_len, 0) != (ssize_t)query_len) {
        return -1;
    }

    uint8_t out_len[2];
    ssize_t n = recv(fd, out_len, sizeof(out_len), MSG_WAITALL);
    if (n != (ssize_t)sizeof(out_len)) {
        return -1;
    }

    size_t resp_len = (size_t)(((uint16_t)out_len[0] << 8) | (uint16_t)out_len[1]);
    if (resp_len == 0 || resp_len > 1500) {
        return -1;
    }

    n = recv(fd, resp_out, resp_len, MSG_WAITALL);
    if (n != (ssize_t)resp_len) {
        return -1;
    }

    *resp_len_out = resp_len;
    return 0;
}

static const char *resolve_proxy_binary_path(void) {
    /* All ready-to-run binaries live in <repo>/build/bin/ regardless of which
     * variant (release/debug/asan/coverage) was configured. The relative path
     * depends on the test's working directory at the time ctest invokes it. */
    static const char *const candidates[] = {
        "./dns-encrypted-proxy",            /* cwd = build/bin/ */
        "../bin/dns-encrypted-proxy",       /* cwd = build/<variant>/ */
        "./build/bin/dns-encrypted-proxy",  /* cwd = repo root */
        "../../bin/dns-encrypted-proxy",    /* cwd = build/matrix/<combo>/ */
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (access(candidates[i], X_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

static int waitpid_with_timeout(pid_t pid, int *status_out, int timeout_ms) {
    if (pid <= 0 || timeout_ms <= 0) {
        return -1;
    }

    int waited_ms = 0;
    while (waited_ms < timeout_ms) {
        int status = 0;
        pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid) {
            if (status_out != NULL) {
                *status_out = status;
            }
            return 0;
        }
        if (rc < 0) {
            return -1;
        }

        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
        waited_ms += 50;
    }

    return -1;
}

static pid_t spawn_main_with_config(const char *config_path) {
    const char *bin = resolve_proxy_binary_path();
    if (bin == NULL || config_path == NULL) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execl(bin, "dns-encrypted-proxy", config_path, (char *)NULL);
        _exit(127);
    }

    return pid;
}

static pid_t spawn_main_without_args(void) {
    const char *bin = resolve_proxy_binary_path();
    if (bin == NULL) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execl(bin, "dns-encrypted-proxy", (char *)NULL);
        _exit(127);
    }

    return pid;
}

typedef struct {
    pid_t pid;
    int port;
    char *script_path;
} python_doh_server_t;

typedef struct {
    pid_t pid;
    int port;
} python_doq_server_t;

static char *bytes_to_hex(const uint8_t *data, size_t len) {
    static const char HEX[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (out == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = HEX[(data[i] >> 4) & 0x0Fu];
        out[2 * i + 1] = HEX[data[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
    return out;
}

static char *create_python_doh_script(const char *response_hex) {
    const char *tmpl =
        "import ssl\n"
        "import sys\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "RESP = bytes.fromhex(\"%s\")\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    protocol_version = \"HTTP/1.1\"\n"
        "    def do_POST(self):\n"
        "        length = int(self.headers.get(\"Content-Length\", \"0\"))\n"
        "        if length > 0:\n"
        "            self.rfile.read(length)\n"
        "        self.send_response(200)\n"
        "        self.send_header(\"Content-Type\", \"application/dns-message\")\n"
        "        self.send_header(\"Content-Length\", str(len(RESP)))\n"
        "        self.send_header(\"Connection\", \"close\")\n"
        "        self.end_headers()\n"
        "        self.wfile.write(RESP)\n"
        "    def log_message(self, format, *args):\n"
        "        return\n"
        "def main():\n"
        "    port = int(sys.argv[1])\n"
        "    cert = sys.argv[2]\n"
        "    key = sys.argv[3]\n"
        "    httpd = HTTPServer((\"127.0.0.1\", port), Handler)\n"
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
        "    ctx.load_cert_chain(certfile=cert, keyfile=key)\n"
        "    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)\n"
        "    httpd.serve_forever()\n"
        "if __name__ == \"__main__\":\n"
        "    main()\n";

    size_t needed = strlen(tmpl) + strlen(response_hex) + 32;
    char *script = malloc(needed);
    if (script == NULL) {
        return NULL;
    }
    int n = snprintf(script, needed, tmpl, response_hex);
    if (n <= 0 || (size_t)n >= needed) {
        free(script);
        return NULL;
    }

    char *path = create_temp_file(script);
    free(script);
    return path;
}

static int start_python_doh_server(
    python_doh_server_t *server,
    const char *cert_path,
    const char *key_path,
    const uint8_t *response,
    size_t response_len) {

    if (server == NULL || cert_path == NULL || key_path == NULL || response == NULL || response_len == 0) {
        return -1;
    }

    memset(server, 0, sizeof(*server));
    server->pid = -1;
    server->port = reserve_unused_port();
    if (server->port <= 0) {
        return -1;
    }

    char *response_hex = bytes_to_hex(response, response_len);
    if (response_hex == NULL) {
        return -1;
    }
    server->script_path = create_python_doh_script(response_hex);
    free(response_hex);
    if (server->script_path == NULL) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        remove_temp_file(server->script_path);
        server->script_path = NULL;
        return -1;
    }

    if (pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", server->port);
        execlp("python3", "python3", server->script_path, port_str, cert_path, key_path, (char *)NULL);
        _exit(127);
    }

    server->pid = pid;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 150 * 1000 * 1000;
    nanosleep(&ts, NULL);

    int child_status = 0;
    pid_t waited = waitpid(server->pid, &child_status, WNOHANG);
    if (waited == server->pid) {
        remove_temp_file(server->script_path);
        server->pid = -1;
        server->script_path = NULL;
        return -1;
    }

    if (waited < 0 || kill(server->pid, 0) != 0) {
        kill(server->pid, SIGTERM);
        waitpid(server->pid, NULL, 0);
        remove_temp_file(server->script_path);
        server->pid = -1;
        server->script_path = NULL;
        return -1;
    }

    return 0;
}

static void stop_python_doh_server(python_doh_server_t *server) {
    if (server == NULL) {
        return;
    }

    if (server->pid > 0) {
        kill(server->pid, SIGTERM);
        waitpid(server->pid, NULL, 0);
        server->pid = -1;
    }

    if (server->script_path != NULL) {
        remove_temp_file(server->script_path);
        server->script_path = NULL;
    }
}

static const char *resolve_mock_doq_script_path(void) {
    if (access("./tools/mock_doq_server.py", R_OK) == 0) {
        return "./tools/mock_doq_server.py";
    }
    if (access("../tools/mock_doq_server.py", R_OK) == 0) {
        return "../tools/mock_doq_server.py";
    }
    return NULL;
}

static int start_python_doq_server(
    python_doq_server_t *server,
    const char *cert_path,
    const char *key_path,
    const char *mode) {
    if (server == NULL || cert_path == NULL || key_path == NULL || mode == NULL) {
        return -1;
    }

    const char *script = resolve_mock_doq_script_path();
    if (script == NULL) {
        return -1;
    }

    memset(server, 0, sizeof(*server));
    server->pid = -1;
    server->port = reserve_unused_port();
    if (server->port <= 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", server->port);
        execlp("python3", "python3", script, port_str, cert_path, key_path, mode, (char *)NULL);
        _exit(127);
    }

    server->pid = pid;

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 200 * 1000 * 1000;
    nanosleep(&ts, NULL);

    int child_status = 0;
    pid_t waited = waitpid(server->pid, &child_status, WNOHANG);
    if (waited == server->pid) {
        server->pid = -1;
        return -1;
    }

    if (waited < 0 || kill(server->pid, 0) != 0) {
        kill(server->pid, SIGTERM);
        waitpid(server->pid, NULL, 0);
        server->pid = -1;
        return -1;
    }

    return 0;
}

static void stop_python_doq_server(python_doq_server_t *server) {
    if (server == NULL) {
        return;
    }

    if (server->pid > 0) {
        kill(server->pid, SIGTERM);
        waitpid(server->pid, NULL, 0);
        server->pid = -1;
    }
}

/*
 * Test: Full cache flow - extract key, store response, lookup with different ID
 */
static void test_cache_flow_end_to_end(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 100);
    
    /* Extract cache key from query */
    uint8_t key[512];
    size_t key_len = 0;
    int result = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key, sizeof(key), &key_len);
    assert_int_equal(result, 0);
    
    /* Verify response is cacheable */
    int cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(cacheable, 1);
    
    /* Get TTL from response */
    int ok = 0;
    uint32_t ttl = dns_response_min_ttl(
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN,
        &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 300);
    
    /* Store in cache */
    dns_cache_store(&cache, key, key_len,
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A,
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN,
                    ttl);
    
    /* Lookup with different request ID */
    uint8_t new_request_id[2] = {0xDE, 0xAD};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit = dns_cache_lookup(&cache, key, key_len, new_request_id, &response, &response_len);
    
    assert_int_equal(hit, 1);
    assert_non_null(response);
    assert_int_equal(response_len, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    
    /* Verify request ID was updated */
    assert_int_equal(response[0], 0xDE);
    assert_int_equal(response[1], 0xAD);
    
    /* Verify rest of response is intact (flags, counts) */
    assert_int_equal(response[2], 0x81);  /* QR=1, Opcode=0, AA=0, TC=0, RD=1 */
    assert_int_equal(response[3], 0x80);  /* RA=1, Z=0, RCODE=0 */
    
    free(response);
    dns_cache_destroy(&cache);
}

/*
 * Test: Case-insensitive cache lookup
 * Query with uppercase should hit cache entry from lowercase query
 */
static void test_cache_case_insensitive(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 100);
    
    /* Extract key from lowercase query */
    uint8_t key_lower[512];
    size_t key_lower_len = 0;
    dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key_lower, sizeof(key_lower), &key_lower_len);
    
    /* Store response */
    dns_cache_store(&cache, key_lower, key_lower_len,
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A,
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN,
                    300);
    
    /* Extract key from uppercase query */
    uint8_t key_upper[512];
    size_t key_upper_len = 0;
    dns_extract_question_key(
        DNS_QUERY_UPPERCASE,
        DNS_QUERY_UPPERCASE_LEN,
        key_upper, sizeof(key_upper), &key_upper_len);
    
    /* Keys should be identical */
    assert_int_equal(key_lower_len, key_upper_len);
    assert_memory_equal(key_lower, key_upper, key_lower_len);
    
    /* Lookup with uppercase key should hit */
    uint8_t request_id[2] = {0x00, 0x00};
    uint8_t *response = NULL;
    size_t response_len = 0;
    
    int hit = dns_cache_lookup(&cache, key_upper, key_upper_len, request_id, &response, &response_len);
    
    assert_int_equal(hit, 1);
    free(response);
    
    dns_cache_destroy(&cache);
}

/*
 * Test: Non-cacheable responses are rejected
 */
static void test_non_cacheable_response_flow(void **state) {
    (void)state;
    
    /* SERVFAIL should not be cached */
    int cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_SERVFAIL,
        DNS_RESPONSE_SERVFAIL_LEN);
    assert_int_equal(cacheable, 0);
    
    /* Truncated should not be cached */
    cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_TRUNCATED,
        DNS_RESPONSE_TRUNCATED_LEN);
    assert_int_equal(cacheable, 0);
}

/*
 * Test: Negative caching with NXDOMAIN
 */
static void test_negative_caching_nxdomain(void **state) {
    (void)state;
    
    /* NXDOMAIN is cacheable */
    int cacheable = dns_response_is_cacheable(
        DNS_RESPONSE_NXDOMAIN,
        DNS_RESPONSE_NXDOMAIN_LEN);
    assert_int_equal(cacheable, 1);
    
    /* TTL should come from SOA minimum */
    int ok = 0;
    uint32_t ttl = dns_response_min_ttl(
        DNS_RESPONSE_NXDOMAIN,
        DNS_RESPONSE_NXDOMAIN_LEN,
        &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 60);  /* SOA minimum from fixture */
}

/*
 * Test: Query/response validation
 */
static void test_query_response_validation(void **state) {
    (void)state;
    
    /* Matching query and response should validate */
    int result = dns_validate_response_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(result, 0);
    
    /* Mismatched query and response should fail */
    result = dns_validate_response_for_query(
        DNS_QUERY_EXAMPLE_COM_AAAA,
        DNS_QUERY_EXAMPLE_COM_AAAA_LEN,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A,
        DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(result, -1);
}

/*
 * Test: EDNS payload size detection
 */
static void test_edns_payload_detection(void **state) {
    (void)state;
    
    /* Query without EDNS -> 512 byte limit */
    size_t limit = dns_udp_payload_limit_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(limit, 512);
    
    /* Query with EDNS (4096) -> 4096 byte limit */
    limit = dns_udp_payload_limit_for_query(
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN);
    assert_int_equal(limit, 4096);
}

/*
 * Test: Configuration defaults are sensible
 */
static void test_config_integration(void **state) {
    (void)state;
    
    clear_config_env_vars();
    
    proxy_config_t config;
    int result = config_load(&config, "/nonexistent");
    
    assert_int_equal(result, 0);
    
    /* Verify critical defaults */
    assert_int_equal(config.listen_port, 53);
    assert_true(config.cache_capacity > 0);
    assert_true(config.upstream_count > 0);
    assert_true(config.upstream_timeout_ms > 0);
    assert_true(config.upstream_pool_size > 0);
}

/*
 * Test: Different EDNS options produce different cache keys
 */
static void test_edns_cache_key_differentiation(void **state) {
    (void)state;
    
    /* Extract key from query without EDNS */
    uint8_t key_no_edns[512];
    size_t key_no_edns_len = 0;
    int result1 = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key_no_edns, sizeof(key_no_edns), &key_no_edns_len);
    
    /* Extract key from query with EDNS */
    uint8_t key_edns[512];
    size_t key_edns_len = 0;
    int result2 = dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
        DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
        key_edns, sizeof(key_edns), &key_edns_len);
    
    assert_int_equal(result1, 0);
    assert_int_equal(result2, 0);
    
    /* Keys should be different due to EDNS presence */
    assert_true(key_no_edns_len != key_edns_len || 
                memcmp(key_no_edns, key_edns, key_no_edns_len) != 0);
}

/*
 * Test: Cache handles concurrent queries for same domain
 */
static void test_cache_concurrent_same_domain(void **state) {
    (void)state;
    
    dns_cache_t cache;
    dns_cache_init(&cache, 100);
    
    /* Extract key */
    uint8_t key[512];
    size_t key_len = 0;
    dns_extract_question_key(
        DNS_QUERY_WWW_EXAMPLE_COM_A,
        DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
        key, sizeof(key), &key_len);
    
    /* Store response */
    dns_cache_store(&cache, key, key_len,
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A,
                    DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN,
                    300);
    
    /* Multiple lookups with different IDs should all succeed */
    for (int i = 0; i < 10; i++) {
        uint8_t request_id[2] = {(uint8_t)i, (uint8_t)(i + 1)};
        uint8_t *response = NULL;
        size_t response_len = 0;
        
        int hit = dns_cache_lookup(&cache, key, key_len, request_id, &response, &response_len);
        
        assert_int_equal(hit, 1);
        assert_non_null(response);
        assert_int_equal(response[0], request_id[0]);
        assert_int_equal(response[1], request_id[1]);
        
        free(response);
    }
    
    dns_cache_destroy(&cache);
}

/*
 * Test: TTL aging in cached responses
 */
static void test_ttl_aging_in_cache(void **state) {
    (void)state;
    
    /* Make a copy of response to test aging */
    uint8_t response[DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN];
    memcpy(response, DNS_RESPONSE_WWW_EXAMPLE_COM_A, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    
    /* Original TTL is 300 */
    int ok = 0;
    uint32_t ttl = dns_response_min_ttl(response, sizeof(response), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 300);
    
    /* Age by 150 seconds */
    int result = dns_adjust_response_ttls(response, sizeof(response), 150);
    assert_int_equal(result, 0);
    
    /* New TTL should be 150 */
    ttl = dns_response_min_ttl(response, sizeof(response), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 150);
    
    /* Age by another 200 seconds (past original TTL) */
    result = dns_adjust_response_ttls(response, sizeof(response), 200);
    assert_int_equal(result, 0);
    
    /* TTL should be clamped to 0 */
    ttl = dns_response_min_ttl(response, sizeof(response), &ok);
    assert_int_equal(ok, 1);
    assert_int_equal(ttl, 0);
}

/*
 * Test: DoH transport path succeeds against local HTTPS mock
 */
#if UPSTREAM_DOH_ENABLED
static void test_upstream_transport_doh_success(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doh_server_t server;
    assert_int_equal(
        start_python_doh_server(
            &server,
            cert_path,
            key_path,
            DNS_RESPONSE_WWW_EXAMPLE_COM_A,
            DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN),
        0);

    setenv("CURL_CA_BUNDLE", cert_path, 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1", "1", 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS", "1", 1);

    char url[256];
    snprintf(url, sizeof(url), "https://localhost:%d/dns-query", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 2,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };

    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    int resolve_rc = -1;
    for (int attempt = 0; attempt < 5; attempt++) {
        resolve_rc = upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len);
        if (resolve_rc == 0) {
            break;
        }
        struct timespec retry_sleep;
        retry_sleep.tv_sec = 0;
        retry_sleep.tv_nsec = 100 * 1000 * 1000;
        nanosleep(&retry_sleep, NULL);
    }
    assert_int_equal(resolve_rc, 0);

    assert_non_null(response);
    assert_int_equal(response_len, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_memory_equal(response, DNS_RESPONSE_WWW_EXAMPLE_COM_A, response_len);

    free(response);
    upstream_client_destroy(&client);
    stop_python_doh_server(&server);
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS");
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1");
    unsetenv("CURL_CA_BUNDLE");
}
#endif

/*
 * Test: DoH transport path handles unreachable endpoint failure
 */
#if UPSTREAM_DOH_ENABLED
static void test_upstream_transport_doh_unreachable(void **state) {
    (void)state;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);

    char url[256];
    snprintf(url, sizeof(url), "https://127.0.0.1:%d/dns-query", dead_port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 250,
        .pool_size = 2,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };

    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);

    assert_null(response);
    assert_int_equal(response_len, 0);
    assert_int_equal(client.servers[0].type, UPSTREAM_TYPE_DOH);
    assert_true(client.servers[0].health.total_queries >= 1);
    upstream_client_destroy(&client);
}
#endif

/*
 * Test: DoT transport path succeeds over local TLS server
 */
static void test_upstream_transport_dot(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    mock_tls_server_t server;
    assert_int_equal(mock_tls_server_start(&server, MOCK_TLS_MODE_DOT, cert_path, key_path), 0);

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "tls://127.0.0.1:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 2,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };

    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        0);

    assert_non_null(response);
    assert_int_equal(response_len, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_memory_equal(response, DNS_RESPONSE_WWW_EXAMPLE_COM_A, response_len);

    free(response);
    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&server);

    assert_int_equal(server.result, 0);

    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoT transport path fails cleanly when endpoint is unreachable
 */
static void test_upstream_transport_dot_unreachable(void **state) {
    (void)state;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);

    char url[256];
    snprintf(url, sizeof(url), "tls://127.0.0.1:%d", dead_port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 250,
        .pool_size = 2,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };

    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);

    assert_null(response);
    assert_int_equal(response_len, 0);
    assert_true(client.servers[0].health.total_queries >= 1);

    upstream_client_destroy(&client);
}

/*
 * Test: DoT transport rejects zero-length framed responses
 */
static void test_upstream_transport_dot_zero_length_response(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    uint8_t dummy = 0;
    mock_tls_server_t server;
    assert_int_equal(mock_tls_server_start(&server, MOCK_TLS_MODE_DOT, cert_path, key_path), 0);
    server.expected_query = DNS_QUERY_WWW_EXAMPLE_COM_A;
    server.expected_query_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    server.response = &dummy;
    server.response_len = 0;

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "tls://127.0.0.1:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 1,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);

    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoT transport rejects malformed response content after read
 */
static void test_upstream_transport_dot_malformed_response(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    static const uint8_t malformed[] = {0x12, 0x34, 0x56};
    mock_tls_server_t server;
    assert_int_equal(mock_tls_server_start(&server, MOCK_TLS_MODE_DOT, cert_path, key_path), 0);
    server.expected_query = DNS_QUERY_WWW_EXAMPLE_COM_A;
    server.expected_query_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    server.response = malformed;
    server.response_len = sizeof(malformed);

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "tls://127.0.0.1:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 1,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);

    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoT transport fails when server closes before sending response length
 */
static void test_upstream_transport_dot_close_before_length(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    mock_tls_server_t server;
    assert_int_equal(mock_tls_server_start(&server, MOCK_TLS_MODE_DOT, cert_path, key_path), 0);
    server.expected_query = DNS_QUERY_WWW_EXAMPLE_COM_A;
    server.expected_query_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    server.dot_close_before_length = 1;

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "tls://127.0.0.1:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 1,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoT transport fails when response body is shorter than announced length
 */
static void test_upstream_transport_dot_partial_body(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    mock_tls_server_t server;
    assert_int_equal(mock_tls_server_start(&server, MOCK_TLS_MODE_DOT, cert_path, key_path), 0);
    server.expected_query = DNS_QUERY_WWW_EXAMPLE_COM_A;
    server.expected_query_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN;
    server.response = DNS_RESPONSE_WWW_EXAMPLE_COM_A;
    server.response_len = DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN;
    server.dot_partial_response_bytes = 4;

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "tls://127.0.0.1:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 1,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&server);
    unsetenv("SSL_CERT_FILE");
}

#if UPSTREAM_DOQ_ENABLED
/*
 * Test: DoQ transport path succeeds against local Python QUIC mock
 */
static void test_upstream_transport_doq_success(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }
    if (system("python3 -c 'import aioquic' >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doq_server_t server;
    if (start_python_doq_server(&server, cert_path, key_path, "ok") != 0) {
        skip();
    }

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "quic://localhost:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 1,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        0);

    assert_non_null(response);
    assert_int_equal(response_len, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN);
    assert_int_equal(response[0], DNS_QUERY_WWW_EXAMPLE_COM_A[0]);
    assert_int_equal(response[1], DNS_QUERY_WWW_EXAMPLE_COM_A[1]);
    assert_true((response[2] & 0x80u) != 0);

    free(response);
    upstream_client_destroy(&client);
    stop_python_doq_server(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoQ transport path fails cleanly when endpoint is unreachable
 */
static void test_upstream_transport_doq_unreachable(void **state) {
    (void)state;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);

    char url[256];
    snprintf(url, sizeof(url), "quic://127.0.0.1:%d", dead_port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 100,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);

    assert_null(response);
    assert_int_equal(response_len, 0);
    assert_true(client.servers[0].health.total_queries >= 1);
    upstream_client_destroy(&client);
}

/*
 * Test: DoQ transport fails when peer negotiates non-DoQ ALPN
 */
static void test_upstream_transport_doq_alpn_mismatch(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }
    if (system("python3 -c 'import aioquic' >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doq_server_t server;
    if (start_python_doq_server(&server, cert_path, key_path, "alpn_mismatch") != 0) {
        skip();
    }

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "quic://localhost:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 300,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    stop_python_doq_server(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoQ transport fails when peer sends malformed framed response length
 */
static void test_upstream_transport_doq_malformed_len(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }
    if (system("python3 -c 'import aioquic' >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doq_server_t server;
    if (start_python_doq_server(&server, cert_path, key_path, "malformed_len") != 0) {
        skip();
    }

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "quic://localhost:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 300,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    stop_python_doq_server(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoQ transport fails when peer never sends FIN on response stream
 */
static void test_upstream_transport_doq_no_fin(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }
    if (system("python3 -c 'import aioquic' >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doq_server_t server;
    if (start_python_doq_server(&server, cert_path, key_path, "no_fin") != 0) {
        skip();
    }

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "quic://localhost:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 300,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    stop_python_doq_server(&server);
    unsetenv("SSL_CERT_FILE");
}

/*
 * Test: DoQ transport fails when peer closes stream early
 */
static void test_upstream_transport_doq_close_early(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }
    if (system("python3 -c 'import aioquic' >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doq_server_t server;
    if (start_python_doq_server(&server, cert_path, key_path, "close_early") != 0) {
        skip();
    }

    setenv("SSL_CERT_FILE", cert_path, 1);

    char url[256];
    snprintf(url, sizeof(url), "quic://localhost:%d", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 300,
        .pool_size = 1,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        -1);
    assert_null(response);
    assert_int_equal(response_len, 0);

    upstream_client_destroy(&client);
    stop_python_doq_server(&server);
    unsetenv("SSL_CERT_FILE");
}
#endif

/*
 * Test: DoH runtime stats record HTTP/1 responses when forced via test env
 */
#if UPSTREAM_DOH_ENABLED
static void test_upstream_transport_doh_http1_runtime_stats(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    python_doh_server_t server;
    assert_int_equal(
        start_python_doh_server(
            &server,
            cert_path,
            key_path,
            DNS_RESPONSE_WWW_EXAMPLE_COM_A,
            DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN),
        0);

    setenv("CURL_CA_BUNDLE", cert_path, 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1", "1", 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS", "1", 1);

    char url[256];
    snprintf(url, sizeof(url), "https://localhost:%d/dns-query", server.port);
    const char *urls[] = {url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 1000,
        .pool_size = 2,
        .max_failures_before_unhealthy = 3,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&client, urls, 1, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        0);
    free(response);

    upstream_runtime_stats_t stats;
    assert_int_equal(upstream_get_runtime_stats(&client, &stats), 0);
    assert_true(stats.doh_http1_responses_total >= 1);

    upstream_client_destroy(&client);
    stop_python_doh_server(&server);
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS");
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1");
    unsetenv("CURL_CA_BUNDLE");
}
#endif

/*
 * Test: Failover from failed DoH upstream to healthy DoT upstream
 */
#if UPSTREAM_DOH_ENABLED && UPSTREAM_DOT_ENABLED
static void test_upstream_transport_failover_doh_to_dot(void **state) {
    (void)state;

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    mock_tls_server_t dot_server;
    assert_int_equal(mock_tls_server_start(&dot_server, MOCK_TLS_MODE_DOT, cert_path, key_path), 0);

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);

    setenv("CURL_CA_BUNDLE", cert_path, 1);
    setenv("SSL_CERT_FILE", cert_path, 1);

    char doh_url[256];
    char dot_url[256];
    snprintf(doh_url, sizeof(doh_url), "https://127.0.0.1:%d/dns-query", dead_port);
    snprintf(dot_url, sizeof(dot_url), "tls://127.0.0.1:%d", dot_server.port);
    const char *urls[] = {doh_url, dot_url};

    upstream_client_t client;
    upstream_config_t cfg = {
        .timeout_ms = 250,
        .pool_size = 2,
        .max_failures_before_unhealthy = 1,
        .unhealthy_backoff_ms = 1000,
    };

    assert_int_equal(upstream_client_init(&client, urls, 2, &cfg), 0);

    uint8_t *response = NULL;
    size_t response_len = 0;
    assert_int_equal(
        upstream_resolve(
            &client,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            &response,
            &response_len),
        0);

    assert_non_null(response);
    assert_int_equal(response_len, DNS_RESPONSE_WWW_EXAMPLE_COM_A_LEN);
    assert_memory_equal(response, DNS_RESPONSE_WWW_EXAMPLE_COM_A, response_len);
    assert_int_equal(client.servers[0].type, UPSTREAM_TYPE_DOH);
    assert_true(client.servers[0].health.total_failures >= 1);

    free(response);
    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&dot_server);

    assert_int_equal(dot_server.result, 0);

    unsetenv("CURL_CA_BUNDLE");
    unsetenv("SSL_CERT_FILE");
}
#endif

/*
 * Test: Metrics endpoint serves prometheus text and 404 for non-metrics routes
 */
static void test_metrics_endpoint_http_paths(void **state) {
    (void)state;

    proxy_metrics_t metrics;
    metrics_init(&metrics);
    atomic_fetch_add(&metrics.queries_udp, 3);

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 32), PROXY_OK);

    int port = reserve_unused_port();
    assert_true(port > 0);
    assert_int_equal(metrics_server_start(&metrics, &cache, NULL, NULL, port), 0);

    char body[32768];
    assert_int_equal(http_get_local(port, "/metrics", body, sizeof(body)), 0);
    assert_non_null(strstr(body, "HTTP/1.1 200 OK"));
    assert_non_null(strstr(body, "# HELP dns_encrypted_proxy_queries_udp_total"));
    assert_non_null(strstr(body, "dns_encrypted_proxy_queries_udp_total 3"));
    assert_non_null(strstr(body, "dns_encrypted_proxy_uptime_seconds"));

    char not_found[2048];
    assert_int_equal(http_get_local(port, "/not-found", not_found, sizeof(not_found)), 0);
    assert_non_null(strstr(not_found, "HTTP/1.1 404 Not Found"));

    assert_true((uint64_t)atomic_load(&metrics.metrics_http_requests_total) >= 2);
    assert_true((uint64_t)atomic_load(&metrics.metrics_http_responses_2xx_total) >= 1);
    assert_true((uint64_t)atomic_load(&metrics.metrics_http_responses_4xx_total) >= 1);
    assert_int_equal((int)atomic_load(&metrics.metrics_http_in_flight), 0);

    metrics_server_stop();
    dns_cache_destroy(&cache);
}

/*
 * Test: Metrics endpoint renders per-upstream labeled series when upstream client is provided
 */
static void test_metrics_endpoint_with_upstream_labels(void **state) {
    (void)state;

    proxy_metrics_t metrics;
    metrics_init(&metrics);

    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 16), PROXY_OK);

    const char *urls[] = {
#if UPSTREAM_DOH_ENABLED
        "https://cloudflare-dns.com/dns-query",
#endif
#if UPSTREAM_DOT_ENABLED
        "tls://1.1.1.1:853",
#endif
#if UPSTREAM_DOQ_ENABLED
        "quic://1.1.1.1:853"
#endif
    };
    upstream_client_t upstream;
    upstream_config_t cfg = {
        .timeout_ms = 250,
        .pool_size = 2,
        .max_failures_before_unhealthy = 2,
        .unhealthy_backoff_ms = 1000,
    };
    assert_int_equal(upstream_client_init(&upstream, urls, sizeof(urls) / sizeof(urls[0]), &cfg), 0);

    int port = reserve_unused_port();
    assert_true(port > 0);
    assert_int_equal(metrics_server_start(&metrics, &cache, &upstream, NULL, port), 0);

    char body[32768];
    assert_int_equal(http_get_local(port, "/metrics", body, sizeof(body)), 0);
#if UPSTREAM_DOH_ENABLED
    assert_non_null(strstr(body, "dns_encrypted_proxy_upstream_server_requests_total{upstream=\"https://cloudflare-dns.com/dns-query\",protocol=\"doh\"}"));
#endif
#if UPSTREAM_DOT_ENABLED
    assert_non_null(strstr(body, "dns_encrypted_proxy_upstream_server_healthy{upstream=\"tls://1.1.1.1:853\",protocol=\"dot\"}"));
#endif
#if UPSTREAM_DOQ_ENABLED
    assert_non_null(strstr(body, "dns_encrypted_proxy_upstream_server_healthy{upstream=\"quic://1.1.1.1:853\",protocol=\"doq\"}"));
#endif

    metrics_server_stop();
    upstream_client_destroy(&upstream);
    dns_cache_destroy(&cache);
}

#if UPSTREAM_DOQ_ENABLED
/*
 * Test: DNS server returns SERVFAIL when DoQ upstream is unreachable and updates counters
 */
static void test_dns_server_udp_servfail_path_doq(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.upstream_timeout_ms = 80;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    uint8_t resp[1500];
    size_t resp_len = 0;
    assert_int_equal(
        send_udp_query_and_recv(
            config.listen_port,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            resp,
            &resp_len),
        0);
    assert_true(resp_len >= 12);

    uint16_t flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    uint16_t rcode = (uint16_t)(flags & 0x000Fu);
    assert_int_equal(rcode, 2);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.queries_udp) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.servfail_sent) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.responses_total) >= 1);

    proxy_server_destroy(&server);
}
#endif

/*
 * Test: DNS server returns SERVFAIL when upstream is unreachable and updates counters
 */
static void test_dns_server_udp_servfail_path(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.upstream_timeout_ms = 150;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    uint8_t resp[1500];
    size_t resp_len = 0;
    assert_int_equal(
        send_udp_query_and_recv(
            config.listen_port,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            resp,
            &resp_len),
        0);
    assert_true(resp_len >= 12);

    uint16_t flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    uint16_t rcode = (uint16_t)(flags & 0x000Fu);
    assert_int_equal(rcode, 2);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.queries_udp) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.servfail_sent) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.responses_total) >= 1);

    proxy_server_destroy(&server);
}

/*
 * Test: DNS server rejects TCP connections at configured max client limit
 */
static void test_dns_server_tcp_connection_rejection(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.tcp_max_clients = 0;
    config.upstream_timeout_ms = 100;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    int fd = open_tcp_connection_local(config.listen_port);
    assert_true(fd >= 0);

    uint8_t byte = 0;
    ssize_t n = recv(fd, &byte, 1, 0);
    assert_int_equal(n, 0);
    close(fd);

    struct timespec settle = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
    nanosleep(&settle, NULL);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.tcp_connections_rejected) >= 1);
    assert_int_equal((uint64_t)atomic_load(&server.metrics.tcp_connections_total), 0);

    proxy_server_destroy(&server);
}

/*
 * Test: DNS server handles TCP query path and returns SERVFAIL on upstream failure
 */
static void test_dns_server_tcp_servfail_path(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.tcp_max_clients = 4;
    config.tcp_max_queries_per_conn = 1;
    config.upstream_timeout_ms = 150;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    uint8_t resp[1500];
    size_t resp_len = 0;
    assert_int_equal(
        send_tcp_query_and_recv(
            config.listen_port,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            resp,
            &resp_len),
        0);
    assert_true(resp_len >= 12);

    uint16_t flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    uint16_t rcode = (uint16_t)(flags & 0x000Fu);
    assert_int_equal(rcode, 2);

    struct timespec settle = {.tv_sec = 0, .tv_nsec = 100 * 1000 * 1000};
    nanosleep(&settle, NULL);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.queries_tcp) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.tcp_connections_total) >= 1);
    assert_true((uint64_t)atomic_load(&server.metrics.servfail_sent) >= 1);

    proxy_server_destroy(&server);
}

/*
 * Test: main exits with non-zero when configuration validation fails
 */
static void test_main_invalid_config_exits_nonzero(void **state) {
    (void)state;

    const char *cfg_text =
        "listen_addr=127.0.0.1\n"
        "listen_port=0\n"
        "upstream_timeout_ms=500\n"
        "upstream_pool_size=2\n"
        "cache_capacity=128\n"
        "upstream_url=https://cloudflare-dns.com/dns-query\n"
        "metrics_enabled=1\n"
        "metrics_port=9090\n";

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);

    pid_t pid = spawn_main_with_config(cfg_path);
    assert_true(pid > 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_not_equal(WEXITSTATUS(status), 0);

    remove_temp_file(cfg_path);
}

/*
 * Test: main starts server and exits cleanly on SIGTERM
 */
static void test_main_start_and_signal_shutdown(void **state) {
    (void)state;

    int listen_port = reserve_unused_port();
    int metrics_port = reserve_unused_port();
    int dead_upstream = reserve_unused_port();
    assert_true(listen_port > 0);
    assert_true(metrics_port > 0);
    assert_true(dead_upstream > 0);

    char cfg_text[1024];
    int n = snprintf(
        cfg_text,
        sizeof(cfg_text),
        "listen_addr=127.0.0.1\n"
        "listen_port=%d\n"
        "upstream_timeout_ms=150\n"
        "upstream_pool_size=1\n"
        "cache_capacity=128\n"
        "upstream_url=https://127.0.0.1:%d/dns-query\n"
        "metrics_enabled=1\n"
        "metrics_port=%d\n",
        listen_port,
        dead_upstream,
        metrics_port);
    assert_true(n > 0 && (size_t)n < sizeof(cfg_text));

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);

    pid_t pid = spawn_main_with_config(cfg_path);
    assert_true(pid > 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 250 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    assert_int_equal(kill(pid, SIGTERM), 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);

    remove_temp_file(cfg_path);
}

/*
 * Test: main exits non-zero when metrics port bind fails
 */
static void test_main_metrics_bind_failure_exits_nonzero(void **state) {
    (void)state;

    int listen_port = reserve_unused_port();
    int dead_upstream = reserve_unused_port();
    int metrics_port = reserve_unused_port();
    assert_true(listen_port > 0);
    assert_true(dead_upstream > 0);
    assert_true(metrics_port > 0);

    int hold_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(hold_fd >= 0);
    int opt = 1;
    setsockopt(hold_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in hold_addr;
    memset(&hold_addr, 0, sizeof(hold_addr));
    hold_addr.sin_family = AF_INET;
    hold_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    hold_addr.sin_port = htons((uint16_t)metrics_port);
    assert_int_equal(bind(hold_fd, (struct sockaddr *)&hold_addr, sizeof(hold_addr)), 0);
    assert_int_equal(listen(hold_fd, 1), 0);

    char cfg_text[1024];
    int n = snprintf(
        cfg_text,
        sizeof(cfg_text),
        "listen_addr=127.0.0.1\n"
        "listen_port=%d\n"
        "upstream_timeout_ms=150\n"
        "upstream_pool_size=1\n"
        "cache_capacity=128\n"
        "upstream_url=https://127.0.0.1:%d/dns-query\n"
        "metrics_enabled=1\n"
        "metrics_port=%d\n",
        listen_port,
        dead_upstream,
        metrics_port);
    assert_true(n > 0 && (size_t)n < sizeof(cfg_text));

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);

    pid_t pid = spawn_main_with_config(cfg_path);
    assert_true(pid > 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_not_equal(WEXITSTATUS(status), 0);

    close(hold_fd);
    remove_temp_file(cfg_path);
}

/*
 * Test: main exits non-zero when server initialization fails after config load
 */
static void test_main_server_init_failure_exits_nonzero(void **state) {
    (void)state;

    int listen_port = reserve_unused_port();
    assert_true(listen_port > 0);

    char cfg_text[1024];
    int n = snprintf(
        cfg_text,
        sizeof(cfg_text),
        "listen_addr=127.0.0.1\n"
        "listen_port=%d\n"
        "upstream_timeout_ms=150\n"
        "upstream_pool_size=1\n"
        "cache_capacity=128\n"
        "upstreams=invalid://not-supported\n"
        "metrics_enabled=0\n"
        "metrics_port=9090\n",
        listen_port);
    assert_true(n > 0 && (size_t)n < sizeof(cfg_text));

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);

    pid_t pid = spawn_main_with_config(cfg_path);
    assert_true(pid > 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_not_equal(WEXITSTATUS(status), 0);

    remove_temp_file(cfg_path);
}

/*
 * Test: main exits non-zero when runtime socket bind fails in proxy_server_run
 */
static void test_main_runtime_bind_failure_exits_nonzero(void **state) {
    (void)state;

    int dead_upstream = reserve_unused_port();
    assert_true(dead_upstream > 0);

    const char *cfg_text =
        "listen_addr=bad.address.example\n"
        "listen_port=5300\n"
        "upstream_timeout_ms=150\n"
        "upstream_pool_size=1\n"
        "cache_capacity=128\n"
#if UPSTREAM_DOH_ENABLED
        "upstream_url=https://127.0.0.1:6553/dns-query\n"
#elif UPSTREAM_DOT_ENABLED
        "upstream_url=tls://127.0.0.1:6553\n"
#else
        "upstream_url=quic://127.0.0.1:6553\n"
#endif
        "metrics_enabled=0\n"
        "metrics_port=9090\n";
    (void)dead_upstream;

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);

    pid_t pid = spawn_main_with_config(cfg_path);
    assert_true(pid > 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_not_equal(WEXITSTATUS(status), 0);

    remove_temp_file(cfg_path);
}

/*
 * Test: main starts with metrics disabled and exits cleanly on SIGTERM
 */
static void test_main_start_metrics_disabled_and_signal_shutdown(void **state) {
    (void)state;

    int listen_port = reserve_unused_port();
    int dead_upstream = reserve_unused_port();
    assert_true(listen_port > 0);
    assert_true(dead_upstream > 0);

    char cfg_text[1024];
    int n = snprintf(
        cfg_text,
        sizeof(cfg_text),
        "listen_addr=127.0.0.1\n"
        "listen_port=%d\n"
        "upstream_timeout_ms=150\n"
        "upstream_pool_size=1\n"
        "cache_capacity=128\n"
#if UPSTREAM_DOH_ENABLED
        "upstreams=https://127.0.0.1:%d/dns-query\n"
#elif UPSTREAM_DOT_ENABLED
        "upstreams=tls://127.0.0.1:%d\n"
#else
        "upstreams=quic://127.0.0.1:%d\n"
#endif
        "metrics_enabled=0\n"
        "metrics_port=9090\n",
        listen_port,
        dead_upstream);
    assert_true(n > 0 && (size_t)n < sizeof(cfg_text));

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);

    pid_t pid = spawn_main_with_config(cfg_path);
    assert_true(pid > 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 250 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    assert_int_equal(kill(pid, SIGTERM), 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);

    remove_temp_file(cfg_path);
}

/*
 * Test: main follows argc==1 path by loading config from DNS_ENCRYPTED_PROXY_CONFIG
 */
static void test_main_no_arg_uses_env_config_and_signal_shutdown(void **state) {
    (void)state;

    int listen_port = reserve_unused_port();
    int dead_upstream = reserve_unused_port();
    assert_true(listen_port > 0);
    assert_true(dead_upstream > 0);

    char cfg_text[1024];
    int n = snprintf(
        cfg_text,
        sizeof(cfg_text),
        "listen_addr=127.0.0.1\n"
        "listen_port=%d\n"
        "upstream_timeout_ms=150\n"
        "upstream_pool_size=1\n"
        "cache_capacity=128\n"
#if UPSTREAM_DOH_ENABLED
        "upstreams=https://127.0.0.1:%d/dns-query\n"
#elif UPSTREAM_DOT_ENABLED
        "upstreams=tls://127.0.0.1:%d\n"
#else
        "upstreams=quic://127.0.0.1:%d\n"
#endif
        "metrics_enabled=0\n"
        "metrics_port=9090\n",
        listen_port,
        dead_upstream);
    assert_true(n > 0 && (size_t)n < sizeof(cfg_text));

    char *cfg_path = create_temp_file(cfg_text);
    assert_non_null(cfg_path);
    setenv("DNS_ENCRYPTED_PROXY_CONFIG", cfg_path, 1);

    pid_t pid = spawn_main_without_args();
    assert_true(pid > 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 250 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    assert_int_equal(kill(pid, SIGTERM), 0);

    int status = 0;
    assert_int_equal(waitpid_with_timeout(pid, &status, 3000), 0);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);

    unsetenv("DNS_ENCRYPTED_PROXY_CONFIG");
    remove_temp_file(cfg_path);
}

/*
 * Test: TCP connection enforces max queries per connection and closes socket
 */
static void test_dns_server_tcp_max_queries_per_connection(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.tcp_max_clients = 2;
    config.tcp_max_queries_per_conn = 1;
    config.upstream_timeout_ms = 150;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    int fd = open_tcp_connection_local(config.listen_port);
    assert_true(fd >= 0);

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t resp[1500];
    size_t resp_len = 0;
    assert_int_equal(send_tcp_query_on_fd(fd, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, resp, &resp_len), 0);
    assert_true(resp_len >= 12);

    size_t resp_len_2 = 0;
    assert_int_equal(send_tcp_query_on_fd(fd, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, resp, &resp_len_2), -1);

    uint8_t b = 0;
    ssize_t n = recv(fd, &b, 1, 0);
    assert_int_equal(n, 0);
    close(fd);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    proxy_server_destroy(&server);
}

/*
 * Test: Proxy and metrics API argument validation guards
 */
static void test_runtime_api_invalid_arguments(void **state) {
    (void)state;

    assert_int_equal(proxy_server_init(NULL, NULL, NULL), -1);
    assert_int_equal(proxy_server_run(NULL), -1);

    proxy_metrics_t metrics;
    metrics_init(&metrics);
    dns_cache_t cache;
    assert_int_equal(dns_cache_init(&cache, 8), PROXY_OK);

    assert_int_equal(metrics_server_start(NULL, &cache, NULL, NULL, 9090), -1);
    assert_int_equal(metrics_server_start(&metrics, &cache, NULL, NULL, 0), -1);
    assert_int_equal(metrics_server_start(&metrics, &cache, NULL, NULL, 70000), -1);

    int busy_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(busy_fd >= 0);
    int opt = 1;
    setsockopt(busy_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int busy_port = reserve_unused_port();
    assert_true(busy_port > 0);

    struct sockaddr_in busy_addr;
    memset(&busy_addr, 0, sizeof(busy_addr));
    busy_addr.sin_family = AF_INET;
    busy_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    busy_addr.sin_port = htons((uint16_t)busy_port);
    assert_int_equal(bind(busy_fd, (struct sockaddr *)&busy_addr, sizeof(busy_addr)), 0);
    assert_int_equal(listen(busy_fd, 1), 0);

    assert_int_equal(metrics_server_start(&metrics, &cache, NULL, NULL, busy_port), -1);
    close(busy_fd);

    metrics_server_stop();

    dns_cache_destroy(&cache);
}

/*
 * Test: TCP zero-length frame is ignored and connection remains usable
 */
static void test_dns_server_tcp_zero_length_frame_ignored(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.tcp_max_clients = 2;
    config.tcp_max_queries_per_conn = 2;
    config.upstream_timeout_ms = 150;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    int fd = open_tcp_connection_local(config.listen_port);
    assert_true(fd >= 0);

    uint8_t zero_len[2] = {0x00, 0x00};
    assert_int_equal(send(fd, zero_len, sizeof(zero_len), 0), (ssize_t)sizeof(zero_len));

    uint8_t resp[1500];
    size_t resp_len = 0;
    assert_int_equal(send_tcp_query_on_fd(fd, DNS_QUERY_WWW_EXAMPLE_COM_A, DNS_QUERY_WWW_EXAMPLE_COM_A_LEN, resp, &resp_len), 0);
    assert_true(resp_len >= 12);

    close(fd);
    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.queries_tcp) >= 1);

    proxy_server_destroy(&server);
}

/*
 * Test: TCP partial length frame close is handled without crashing server loop
 */
static void test_dns_server_tcp_partial_frame_close(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.tcp_max_clients = 4;
    config.tcp_max_queries_per_conn = 0;
    config.upstream_timeout_ms = 150;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    int fd = open_tcp_connection_local(config.listen_port);
    assert_true(fd >= 0);
    uint8_t half_len = 0x00;
    assert_int_equal(send(fd, &half_len, 1, 0), 1);
    close(fd);

    struct timespec settle = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&settle, NULL);

    uint8_t udp_resp[1500];
    size_t udp_resp_len = 0;
    assert_int_equal(
        send_udp_query_and_recv(
            config.listen_port,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            udp_resp,
            &udp_resp_len),
        0);
    assert_true(udp_resp_len >= 12);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.tcp_connections_total) >= 1);

    proxy_server_destroy(&server);
}

/*
 * Test: UDP path truncates oversized upstream response for non-EDNS query
 */
#if UPSTREAM_DOH_ENABLED
static void test_dns_server_udp_truncation_path(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    const size_t answer_count = 40;
    const size_t question_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN - 12;
    const size_t answer_len = 16;
    size_t large_len = 12 + question_len + (answer_count * answer_len);
    uint8_t *large_response = calloc(1, large_len);
    assert_non_null(large_response);

    large_response[0] = 0x12;
    large_response[1] = 0x34;
    large_response[2] = 0x81;
    large_response[3] = 0x80;
    large_response[4] = 0x00;
    large_response[5] = 0x01;
    large_response[6] = (uint8_t)((answer_count >> 8) & 0xFFu);
    large_response[7] = (uint8_t)(answer_count & 0xFFu);
    large_response[8] = 0x00;
    large_response[9] = 0x00;
    large_response[10] = 0x00;
    large_response[11] = 0x00;

    memcpy(large_response + 12, DNS_QUERY_WWW_EXAMPLE_COM_A + 12, question_len);
    size_t off = 12 + question_len;
    for (size_t i = 0; i < answer_count; i++) {
        large_response[off + 0] = 0xC0;
        large_response[off + 1] = 0x0C;
        large_response[off + 2] = 0x00;
        large_response[off + 3] = 0x01;
        large_response[off + 4] = 0x00;
        large_response[off + 5] = 0x01;
        large_response[off + 6] = 0x00;
        large_response[off + 7] = 0x00;
        large_response[off + 8] = 0x01;
        large_response[off + 9] = 0x2C;
        large_response[off + 10] = 0x00;
        large_response[off + 11] = 0x04;
        large_response[off + 12] = 0x5D;
        large_response[off + 13] = 0xB8;
        large_response[off + 14] = 0xD8;
        large_response[off + 15] = (uint8_t)(0x22u + (i & 0x0Fu));
        off += answer_len;
    }

    python_doh_server_t doh_server;
    assert_int_equal(
        start_python_doh_server(
            &doh_server,
            cert_path,
            key_path,
            large_response,
            large_len),
        0);
    free(large_response);

    setenv("CURL_CA_BUNDLE", cert_path, 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1", "1", 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS", "1", 1);

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.upstream_timeout_ms = 1000;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://localhost:%d/dns-query", doh_server.port);

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    uint8_t resp[1500];
    size_t resp_len = 0;
    assert_int_equal(
        send_udp_query_and_recv(
            config.listen_port,
            DNS_QUERY_WWW_EXAMPLE_COM_A,
            DNS_QUERY_WWW_EXAMPLE_COM_A_LEN,
            resp,
            &resp_len),
        0);

    assert_true(resp_len <= 512);
    uint16_t flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    assert_true((flags & 0x0200u) != 0);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.truncated_sent) >= 1);

    proxy_server_destroy(&server);
    stop_python_doh_server(&doh_server);
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS");
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1");
    unsetenv("CURL_CA_BUNDLE");
}

#endif

/*
 * Test: TCP idle timeout closes silent client connection
 */
static void test_dns_server_tcp_idle_timeout_close(void **state) {
    (void)state;

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.tcp_max_clients = 2;
    config.tcp_idle_timeout_ms = 120;
    config.tcp_max_queries_per_conn = 0;
    config.upstream_timeout_ms = 150;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;

    int dead_port = reserve_unused_port();
    assert_true(dead_port > 0);
#if UPSTREAM_DOH_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://127.0.0.1:%d/dns-query", dead_port);
#elif UPSTREAM_DOT_ENABLED
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "tls://127.0.0.1:%d", dead_port);
#else
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "quic://127.0.0.1:%d", dead_port);
#endif

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    int fd = open_tcp_connection_local(config.listen_port);
    assert_true(fd >= 0);

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct timespec idle_wait = {.tv_sec = 0, .tv_nsec = 300 * 1000 * 1000};
    nanosleep(&idle_wait, NULL);

    uint8_t b = 0;
    ssize_t n = recv(fd, &b, 1, 0);
    assert_int_equal(n, 0);
    close(fd);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_true((uint64_t)atomic_load(&server.metrics.tcp_connections_total) >= 1);
    assert_int_equal((uint64_t)atomic_load(&server.metrics.tcp_connections_active), 0);

    proxy_server_destroy(&server);
}

/*
 * Test: EDNS query keeps oversized UDP response untruncated (no TC)
 */
#if UPSTREAM_DOH_ENABLED
static void test_dns_server_udp_edns_no_truncation(void **state) {
    (void)state;

    if (system("python3 -V >/dev/null 2>&1") != 0) {
        skip();
    }

    char cert_path[256];
    char key_path[256];
    assert_int_equal(resolve_test_cert_paths(cert_path, sizeof(cert_path), key_path, sizeof(key_path)), 0);

    const size_t answer_count = 40;
    const size_t question_len = DNS_QUERY_WWW_EXAMPLE_COM_A_LEN - 12;
    const size_t answer_len = 16;
    size_t large_len = 12 + question_len + (answer_count * answer_len);
    uint8_t *large_response = calloc(1, large_len);
    assert_non_null(large_response);

    large_response[0] = 0x12;
    large_response[1] = 0x34;
    large_response[2] = 0x81;
    large_response[3] = 0x80;
    large_response[4] = 0x00;
    large_response[5] = 0x01;
    large_response[6] = (uint8_t)((answer_count >> 8) & 0xFFu);
    large_response[7] = (uint8_t)(answer_count & 0xFFu);
    large_response[8] = 0x00;
    large_response[9] = 0x00;
    large_response[10] = 0x00;
    large_response[11] = 0x00;

    memcpy(large_response + 12, DNS_QUERY_WWW_EXAMPLE_COM_A + 12, question_len);
    size_t off = 12 + question_len;
    for (size_t i = 0; i < answer_count; i++) {
        large_response[off + 0] = 0xC0;
        large_response[off + 1] = 0x0C;
        large_response[off + 2] = 0x00;
        large_response[off + 3] = 0x01;
        large_response[off + 4] = 0x00;
        large_response[off + 5] = 0x01;
        large_response[off + 6] = 0x00;
        large_response[off + 7] = 0x00;
        large_response[off + 8] = 0x01;
        large_response[off + 9] = 0x2C;
        large_response[off + 10] = 0x00;
        large_response[off + 11] = 0x04;
        large_response[off + 12] = 0x5D;
        large_response[off + 13] = 0xB8;
        large_response[off + 14] = 0xD8;
        large_response[off + 15] = (uint8_t)(0x22u + (i & 0x0Fu));
        off += answer_len;
    }

    python_doh_server_t doh_server;
    assert_int_equal(
        start_python_doh_server(
            &doh_server,
            cert_path,
            key_path,
            large_response,
            large_len),
        0);
    free(large_response);

    setenv("CURL_CA_BUNDLE", cert_path, 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1", "1", 1);
    setenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS", "1", 1);

    proxy_config_t config;
    assert_int_equal(config_load(&config, "/nonexistent"), 0);
    strncpy(config.listen_addr, "127.0.0.1", sizeof(config.listen_addr) - 1);
    config.listen_addr[sizeof(config.listen_addr) - 1] = '\0';
    config.listen_port = reserve_unused_port();
    assert_true(config.listen_port > 0);
    config.upstream_timeout_ms = 1000;
    config.upstream_pool_size = 1;
    config.upstream_count = 1;
    snprintf(config.upstream_urls[0], sizeof(config.upstream_urls[0]), "https://localhost:%d/dns-query", doh_server.port);

    volatile sig_atomic_t stop = 0;
    proxy_server_t server;
    assert_int_equal(proxy_server_init(&server, &config, &stop), 0);

    proxy_thread_ctx_t ctx = {.server = &server, .rc = -1};
    pthread_t thread;
    assert_int_equal(pthread_create(&thread, NULL, proxy_server_thread_main, &ctx), 0);

    struct timespec startup_wait = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
    nanosleep(&startup_wait, NULL);

    uint8_t resp[4096];
    size_t resp_len = 0;
    assert_int_equal(
        send_udp_query_and_recv(
            config.listen_port,
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS,
            DNS_QUERY_WWW_EXAMPLE_COM_A_EDNS_LEN,
            resp,
            &resp_len),
        0);

    assert_true(resp_len > 512);
    uint16_t flags = (uint16_t)(((uint16_t)resp[2] << 8) | (uint16_t)resp[3]);
    assert_true((flags & 0x0200u) == 0);

    stop = 1;
    pthread_join(thread, NULL);
    assert_int_equal(ctx.rc, 0);

    assert_int_equal((uint64_t)atomic_load(&server.metrics.truncated_sent), 0);

    proxy_server_destroy(&server);
    stop_python_doh_server(&doh_server);
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_INSECURE_TLS");
    unsetenv("DNS_ENCRYPTED_PROXY_TEST_FORCE_HTTP1");
    unsetenv("CURL_CA_BUNDLE");
}
#endif

int main(void) {
    signal(SIGPIPE, SIG_IGN);

#if defined(INTEGRATION_GROUP_CORE)
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cache_flow_end_to_end),
        cmocka_unit_test(test_cache_case_insensitive),
        cmocka_unit_test(test_non_cacheable_response_flow),
        cmocka_unit_test(test_negative_caching_nxdomain),
        cmocka_unit_test(test_query_response_validation),
        cmocka_unit_test(test_edns_payload_detection),
        cmocka_unit_test(test_config_integration),
        cmocka_unit_test(test_edns_cache_key_differentiation),
        cmocka_unit_test(test_cache_concurrent_same_domain),
        cmocka_unit_test(test_ttl_aging_in_cache),
    };
#elif defined(INTEGRATION_GROUP_TRANSPORT)
    const struct CMUnitTest tests[] = {
#if UPSTREAM_DOH_ENABLED
        cmocka_unit_test(test_upstream_transport_doh_success),
        cmocka_unit_test(test_upstream_transport_doh_unreachable),
        cmocka_unit_test(test_upstream_transport_doh_http1_runtime_stats),
#endif
#if UPSTREAM_DOT_ENABLED
        cmocka_unit_test(test_upstream_transport_dot),
        cmocka_unit_test(test_upstream_transport_dot_unreachable),
        cmocka_unit_test(test_upstream_transport_dot_zero_length_response),
        cmocka_unit_test(test_upstream_transport_dot_malformed_response),
        cmocka_unit_test(test_upstream_transport_dot_close_before_length),
        cmocka_unit_test(test_upstream_transport_dot_partial_body),
#endif
#if UPSTREAM_DOQ_ENABLED
        cmocka_unit_test(test_upstream_transport_doq_success),
        cmocka_unit_test(test_upstream_transport_doq_unreachable),
        cmocka_unit_test(test_upstream_transport_doq_alpn_mismatch),
        cmocka_unit_test(test_upstream_transport_doq_malformed_len),
        cmocka_unit_test(test_upstream_transport_doq_no_fin),
        cmocka_unit_test(test_upstream_transport_doq_close_early),
#endif
#if UPSTREAM_DOH_ENABLED && UPSTREAM_DOT_ENABLED
        cmocka_unit_test(test_upstream_transport_failover_doh_to_dot),
#endif
        cmocka_unit_test(test_metrics_endpoint_with_upstream_labels),
    };
#elif defined(INTEGRATION_GROUP_RUNTIME)
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_metrics_endpoint_http_paths),
        cmocka_unit_test(test_dns_server_udp_servfail_path),
#if UPSTREAM_DOQ_ENABLED
        cmocka_unit_test(test_dns_server_udp_servfail_path_doq),
#endif
        cmocka_unit_test(test_dns_server_tcp_connection_rejection),
        cmocka_unit_test(test_dns_server_tcp_servfail_path),
        cmocka_unit_test(test_main_invalid_config_exits_nonzero),
        cmocka_unit_test(test_main_start_and_signal_shutdown),
        cmocka_unit_test(test_main_metrics_bind_failure_exits_nonzero),
        cmocka_unit_test(test_main_server_init_failure_exits_nonzero),
        cmocka_unit_test(test_main_runtime_bind_failure_exits_nonzero),
        cmocka_unit_test(test_main_start_metrics_disabled_and_signal_shutdown),
        cmocka_unit_test(test_main_no_arg_uses_env_config_and_signal_shutdown),
        cmocka_unit_test(test_dns_server_tcp_max_queries_per_connection),
        cmocka_unit_test(test_runtime_api_invalid_arguments),
        cmocka_unit_test(test_dns_server_tcp_zero_length_frame_ignored),
        cmocka_unit_test(test_dns_server_tcp_partial_frame_close),
#if UPSTREAM_DOH_ENABLED
        cmocka_unit_test(test_dns_server_udp_truncation_path),
#endif
        cmocka_unit_test(test_dns_server_tcp_idle_timeout_close),
#if UPSTREAM_DOH_ENABLED
        cmocka_unit_test(test_dns_server_udp_edns_no_truncation),
#endif
    };
#else
#error "Define one integration group macro"
#endif
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
