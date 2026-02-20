/*
 * Integration tests for DOH-Proxy
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
#include "dns_message.h"
#include "upstream.h"
#include "test_helpers.h"
#include "test_fixtures.h"

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

    if (server->response_len > 65535) {
        result = -1;
        goto done;
    }

    uint8_t resp_len[2];
    resp_len[0] = (uint8_t)((server->response_len >> 8) & 0xFFu);
    resp_len[1] = (uint8_t)(server->response_len & 0xFFu);

    if (ssl_write_all(ssl, resp_len, sizeof(resp_len)) != 0 ||
        ssl_write_all(ssl, server->response, server->response_len) != 0) {
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
    const char *cert_candidates[] = {
        "tests/certs/localhost.cert.pem",
        "../tests/certs/localhost.cert.pem"
    };
    const char *key_candidates[] = {
        "tests/certs/localhost.key.pem",
        "../tests/certs/localhost.key.pem"
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

typedef struct {
    pid_t pid;
    int port;
    char *script_path;
} python_doh_server_t;

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
    setenv("DOH_PROXY_TEST_FORCE_HTTP1", "1", 1);
    setenv("DOH_PROXY_TEST_INSECURE_TLS", "1", 1);

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
    unsetenv("DOH_PROXY_TEST_INSECURE_TLS");
    unsetenv("DOH_PROXY_TEST_FORCE_HTTP1");
    unsetenv("CURL_CA_BUNDLE");
}

/*
 * Test: DoH transport path handles unreachable endpoint failure
 */
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
    assert_true(client.servers[0].health.total_failures >= 1);
    upstream_client_destroy(&client);
}

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
 * Test: Failover from failed DoH upstream to healthy DoT upstream
 */
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
    assert_int_equal(client.servers[0].health.total_failures, 1);

    free(response);
    upstream_client_destroy(&client);
    mock_tls_server_join_and_destroy(&dot_server);

    assert_int_equal(dot_server.result, 0);

    unsetenv("CURL_CA_BUNDLE");
    unsetenv("SSL_CERT_FILE");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

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
        cmocka_unit_test(test_upstream_transport_doh_success),
        cmocka_unit_test(test_upstream_transport_doh_unreachable),
        cmocka_unit_test(test_upstream_transport_dot),
        cmocka_unit_test(test_upstream_transport_failover_doh_to_dot),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
