#define _POSIX_C_SOURCE 200809L

#include "upstream.h"

#if UPSTREAM_DOQ_NGTCP2_ENABLED

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DOQ_MAX_DNS_MESSAGE_SIZE 65535u

typedef struct {
    ngtcp2_conn *conn;
    ngtcp2_crypto_ossl_ctx *crypto_ctx;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_crypto_conn_ref conn_ref;
    struct sockaddr_storage local_addr_storage;
    struct sockaddr_storage remote_addr_storage;
    ngtcp2_path path;

    int64_t stream_id;
    uint8_t stream_rx[2 + DOQ_MAX_DNS_MESSAGE_SIZE];
    size_t stream_rx_len;
    size_t stream_expected_len;
    int stream_fin;
    int stream_response_ready;
} doq_ngtcp2_session_t;

static void write_u16(uint8_t *ptr, uint16_t value) {
    ptr[0] = (uint8_t)((value >> 8) & 0xFFu);
    ptr[1] = (uint8_t)(value & 0xFFu);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void fill_random_bytes(uint8_t *buffer, size_t len) {
    if (buffer == NULL || len == 0) {
        return;
    }

    if (RAND_bytes(buffer, (int)len) == 1) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        buffer[i] = (uint8_t)(rand() & 0xFF);
    }
}

static int connect_udp_with_timeout(const struct addrinfo *ai, int timeout_ms) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        return -1;
    }

    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
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
    rc = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 0);
    if (rc <= 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        close(fd);
        return -1;
    }

    int sock_error = 0;
    socklen_t sock_error_len = sizeof(sock_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_error, &sock_error_len) != 0 || sock_error != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int doq_prepare_query_stream_data(
    const uint8_t *query,
    size_t query_len,
    uint8_t *buffer,
    size_t *buffer_len_out) {
    if (query == NULL || query_len == 0 || buffer == NULL || buffer_len_out == NULL) {
        return -1;
    }
    if (query_len > DOQ_MAX_DNS_MESSAGE_SIZE) {
        return -1;
    }

    write_u16(buffer, (uint16_t)query_len);
    memcpy(buffer + 2, query, query_len);
    *buffer_len_out = query_len + 2;
    return 0;
}

static void doq_ngtcp2_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    (void)rand_ctx;
    fill_random_bytes(dest, destlen);
}

static int doq_ngtcp2_get_new_connection_id(
    ngtcp2_conn *conn,
    ngtcp2_cid *cid,
    uint8_t *token,
    size_t cidlen,
    void *user_data) {
    (void)conn;
    (void)user_data;

    if (cid == NULL || token == NULL || cidlen == 0 || cidlen > NGTCP2_MAX_CIDLEN) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    fill_random_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    fill_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int doq_ngtcp2_get_path_challenge_data(ngtcp2_conn *conn, uint8_t *data, void *user_data) {
    (void)conn;
    (void)user_data;
    if (data == NULL) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    fill_random_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN);
    return 0;
}

static ngtcp2_conn *doq_ngtcp2_get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    if (conn_ref == NULL || conn_ref->user_data == NULL) {
        return NULL;
    }
    doq_ngtcp2_session_t *session = (doq_ngtcp2_session_t *)conn_ref->user_data;
    return session->conn;
}

static int doq_ngtcp2_recv_stream_data(
    ngtcp2_conn *conn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t offset,
    const uint8_t *data,
    size_t datalen,
    void *user_data,
    void *stream_user_data) {
    (void)conn;
    (void)stream_user_data;

    doq_ngtcp2_session_t *session = (doq_ngtcp2_session_t *)user_data;
    if (session == NULL) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (stream_id != session->stream_id) {
        return 0;
    }
    if (offset != session->stream_rx_len) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (datalen > sizeof(session->stream_rx) - session->stream_rx_len) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (datalen > 0 && data != NULL) {
        memcpy(session->stream_rx + session->stream_rx_len, data, datalen);
        session->stream_rx_len += datalen;
    }

    if (session->stream_expected_len == 0 && session->stream_rx_len >= 2) {
        uint16_t dns_len = (uint16_t)(((uint16_t)session->stream_rx[0] << 8) | session->stream_rx[1]);
        session->stream_expected_len = (size_t)dns_len + 2;
        if (session->stream_expected_len > sizeof(session->stream_rx)) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (session->stream_expected_len > 0 && session->stream_rx_len > session->stream_expected_len) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0) {
        session->stream_fin = 1;
    }

    if (session->stream_fin && session->stream_expected_len > 0 &&
        session->stream_rx_len == session->stream_expected_len) {
        session->stream_response_ready = 1;
    }

    return 0;
}

static void doq_ngtcp2_session_cleanup(doq_ngtcp2_session_t *session) {
    if (session == NULL) {
        return;
    }

    if (session->conn != NULL) {
        ngtcp2_conn_del(session->conn);
        session->conn = NULL;
    }

    if (session->crypto_ctx != NULL) {
        ngtcp2_crypto_ossl_ctx_del(session->crypto_ctx);
        session->crypto_ctx = NULL;
    }

    if (session->ssl != NULL) {
        SSL_set_app_data(session->ssl, NULL);
        SSL_free(session->ssl);
        session->ssl = NULL;
    }

    if (session->ssl_ctx != NULL) {
        SSL_CTX_free(session->ssl_ctx);
        session->ssl_ctx = NULL;
    }
}

static int doq_ngtcp2_session_init(doq_ngtcp2_session_t *session, int fd, const upstream_server_t *server) {
    if (session == NULL || fd < 0 || server == NULL) {
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->stream_id = -1;

    if (ngtcp2_crypto_ossl_init() != 0) {
        return -1;
    }

    session->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (session->ssl_ctx == NULL) {
        return -1;
    }
    SSL_CTX_set_verify(session->ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_min_proto_version(session->ssl_ctx, TLS1_3_VERSION);
    if (SSL_CTX_set_default_verify_paths(session->ssl_ctx) != 1) {
        return -1;
    }

    session->ssl = SSL_new(session->ssl_ctx);
    if (session->ssl == NULL) {
        return -1;
    }
    if (SSL_set_tlsext_host_name(session->ssl, server->host) != 1) {
        return -1;
    }
    if (SSL_set1_host(session->ssl, server->host) != 1) {
        return -1;
    }

    static const uint8_t doq_alpn[] = {0x03, 'd', 'o', 'q'};
    if (SSL_set_alpn_protos(session->ssl, doq_alpn, (unsigned int)sizeof(doq_alpn)) != 0) {
        return -1;
    }
    SSL_set_connect_state(session->ssl);

    socklen_t local_len = sizeof(session->local_addr_storage);
    socklen_t remote_len = sizeof(session->remote_addr_storage);
    if (getsockname(fd, (struct sockaddr *)&session->local_addr_storage, &local_len) != 0) {
        return -1;
    }
    if (getpeername(fd, (struct sockaddr *)&session->remote_addr_storage, &remote_len) != 0) {
        return -1;
    }

    ngtcp2_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = doq_ngtcp2_recv_stream_data;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.rand = doq_ngtcp2_rand;
    callbacks.get_new_connection_id = doq_ngtcp2_get_new_connection_id;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = doq_ngtcp2_get_path_challenge_data;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_data = 65536;
    params.initial_max_stream_data_bidi_local = 32768;
    params.initial_max_stream_data_bidi_remote = 32768;
    params.initial_max_stream_data_uni = 32768;
    params.initial_max_streams_bidi = 1;
    params.initial_max_streams_uni = 1;

    uint8_t scid_data[16];
    uint8_t dcid_data[16];
    fill_random_bytes(scid_data, sizeof(scid_data));
    fill_random_bytes(dcid_data, sizeof(dcid_data));
    ngtcp2_cid scid;
    ngtcp2_cid dcid;
    ngtcp2_cid_init(&scid, scid_data, sizeof(scid_data));
    ngtcp2_cid_init(&dcid, dcid_data, sizeof(dcid_data));

    session->path.local.addr = (struct sockaddr *)&session->local_addr_storage;
    session->path.local.addrlen = local_len;
    session->path.remote.addr = (struct sockaddr *)&session->remote_addr_storage;
    session->path.remote.addrlen = remote_len;
    session->path.user_data = NULL;

    if (ngtcp2_conn_client_new(
            &session->conn,
            &dcid,
            &scid,
            &session->path,
            NGTCP2_PROTO_VER_V1,
            &callbacks,
            &settings,
            &params,
            NULL,
            session)
        != 0) {
        return -1;
    }

    session->conn_ref.get_conn = doq_ngtcp2_get_conn;
    session->conn_ref.user_data = session;
    SSL_set_app_data(session->ssl, &session->conn_ref);

    if (ngtcp2_crypto_ossl_configure_client_session(session->ssl) != 0) {
        return -1;
    }
    if (ngtcp2_crypto_ossl_ctx_new(&session->crypto_ctx, session->ssl) != 0) {
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(session->conn, session->crypto_ctx);

    return 0;
}

static int doq_ngtcp2_wait_for_io(int fd, uint64_t deadline_ns) {
    if (fd < 0) {
        return -1;
    }

    uint64_t now = now_ns();
    int timeout_ms = 0;
    if (deadline_ns > now) {
        timeout_ms = (int)((deadline_ns - now) / 1000000ULL);
        if (timeout_ms <= 0) {
            timeout_ms = 1;
        }
    }

    struct pollfd pfd = {0};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int prc = poll(&pfd, 1, timeout_ms);
    if (prc < 0) {
        return -1;
    }
    return prc;
}

static int doq_ngtcp2_handle_timers(doq_ngtcp2_session_t *session) {
    if (session == NULL || session->conn == NULL) {
        return -1;
    }

    uint64_t now = now_ns();
    if (now >= ngtcp2_conn_get_expiry(session->conn)) {
        if (ngtcp2_conn_handle_expiry(session->conn, now) != 0) {
            return -1;
        }
    }

    return 0;
}

static int doq_ngtcp2_send_generated_packet(doq_ngtcp2_session_t *session, int fd) {
    if (session == NULL || session->conn == NULL || fd < 0) {
        return -1;
    }

    uint8_t tx_buffer[1350];
    ngtcp2_pkt_info tx_pi;
    memset(&tx_pi, 0, sizeof(tx_pi));

    ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
        session->conn,
        &session->path,
        &tx_pi,
        tx_buffer,
        sizeof(tx_buffer),
        now_ns());
    if (nwrite < 0) {
        return -1;
    }
    ngtcp2_conn_update_pkt_tx_time(session->conn, now_ns());

    if (nwrite > 0) {
        ssize_t nsent = send(fd, tx_buffer, (size_t)nwrite, 0);
        if (nsent != nwrite) {
            return -1;
        }
    }

    return 0;
}

static int doq_ngtcp2_send_stream_data(
    doq_ngtcp2_session_t *session,
    int fd,
    const uint8_t *stream_data,
    size_t stream_data_len,
    size_t *stream_offset,
    int *stream_fin_sent) {
    if (session == NULL || session->conn == NULL || fd < 0 || stream_data == NULL ||
        stream_offset == NULL || stream_fin_sent == NULL) {
        return -1;
    }

    for (int i = 0; i < 4; i++) {
        ngtcp2_vec vec;
        ngtcp2_vec *vec_ptr = NULL;
        size_t vec_count = 0;
        ngtcp2_ssize pdatalen = -1;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;

        if (*stream_offset < stream_data_len) {
            vec.base = (uint8_t *)(stream_data + *stream_offset);
            vec.len = stream_data_len - *stream_offset;
            vec_ptr = &vec;
            vec_count = 1;
            if (!*stream_fin_sent) {
                flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            }
        } else if (!*stream_fin_sent) {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        } else {
            return 0;
        }

        uint8_t tx_buffer[1350];
        ngtcp2_pkt_info tx_pi;
        memset(&tx_pi, 0, sizeof(tx_pi));
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            session->conn,
            &session->path,
            &tx_pi,
            tx_buffer,
            sizeof(tx_buffer),
            &pdatalen,
            flags,
            session->stream_id,
            vec_ptr,
            vec_count,
            now_ns());
        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED || nwrite == NGTCP2_ERR_WRITE_MORE) {
                continue;
            }
            return -1;
        }

        ngtcp2_conn_update_pkt_tx_time(session->conn, now_ns());

        if (pdatalen > 0) {
            *stream_offset += (size_t)pdatalen;
        }
        if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) != 0 && *stream_offset == stream_data_len && pdatalen >= 0) {
            *stream_fin_sent = 1;
        }

        if (nwrite > 0) {
            ssize_t nsent = send(fd, tx_buffer, (size_t)nwrite, 0);
            if (nsent != nwrite) {
                return -1;
            }
        }

        if (nwrite == 0 && pdatalen < 0) {
            break;
        }
    }

    return 0;
}

static int doq_ngtcp2_receive_packets(doq_ngtcp2_session_t *session, int fd) {
    if (session == NULL || session->conn == NULL || fd < 0) {
        return -1;
    }

    for (;;) {
        uint8_t rx_buffer[4096];
        ssize_t nread = recv(fd, rx_buffer, sizeof(rx_buffer), 0);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return -1;
        }
        if (nread == 0) {
            return -1;
        }

        ngtcp2_pkt_info rx_pi;
        memset(&rx_pi, 0, sizeof(rx_pi));
        if (ngtcp2_conn_read_pkt(
                session->conn,
                &session->path,
                &rx_pi,
                rx_buffer,
                (size_t)nread,
                now_ns())
            != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * ngtcp2-backed DoQ transport entrypoint.
 *
 * NOTE:
 * This now drives a full client connection attempt: QUIC handshake, DoQ stream
 * open, framed DNS query send, and framed DNS response read.
 */
int upstream_doq_ngtcp2_resolve(
    const upstream_server_t *server,
    int timeout_ms,
    const uint8_t *query,
    size_t query_len,
    uint8_t **response_out,
    size_t *response_len_out) {
    if (server == NULL || query == NULL || query_len == 0 || response_out == NULL || response_len_out == NULL) {
        return -1;
    }
    if (query_len > DOQ_MAX_DNS_MESSAGE_SIZE) {
        return -1;
    }
    if (server->host[0] == '\0' || server->port <= 0 || server->port > 65535) {
        return -1;
    }

    *response_out = NULL;
    *response_len_out = 0;

    uint8_t stream_data[2 + DOQ_MAX_DNS_MESSAGE_SIZE];
    size_t stream_data_len = 0;
    if (doq_prepare_query_stream_data(query, query_len, stream_data, &stream_data_len) != 0) {
        return -1;
    }

    char port_text[16];
    if (snprintf(port_text, sizeof(port_text), "%d", server->port) <= 0) {
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *res = NULL;
    if (getaddrinfo(server->host, port_text, &hints, &res) != 0 || res == NULL) {
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = connect_udp_with_timeout(ai, timeout_ms);
        if (fd >= 0) {
            break;
        }
    }
    freeaddrinfo(res);

    if (fd < 0) {
        return -1;
    }

    doq_ngtcp2_session_t session;
    if (doq_ngtcp2_session_init(&session, fd, server) != 0) {
        close(fd);
        return -1;
    }

    int effective_timeout_ms = timeout_ms > 0 ? timeout_ms : 1000;
    uint64_t deadline = now_ns() + (uint64_t)effective_timeout_ms * 1000000ULL;
    int result = -1;

    while (now_ns() < deadline) {
        if (doq_ngtcp2_send_generated_packet(&session, fd) != 0) {
            break;
        }
        if (doq_ngtcp2_wait_for_io(fd, deadline) < 0) {
            break;
        }
        if (doq_ngtcp2_receive_packets(&session, fd) != 0) {
            break;
        }
        if (doq_ngtcp2_handle_timers(&session) != 0) {
            break;
        }
        if (ngtcp2_conn_get_handshake_completed(session.conn) != 0) {
            break;
        }
    }

    if (ngtcp2_conn_get_handshake_completed(session.conn) != 0) {
        const unsigned char *selected_alpn = NULL;
        unsigned int selected_alpn_len = 0;
        SSL_get0_alpn_selected(session.ssl, &selected_alpn, &selected_alpn_len);

        if (selected_alpn != NULL && selected_alpn_len == 3 && memcmp(selected_alpn, "doq", 3) == 0 &&
            ngtcp2_conn_open_bidi_stream(session.conn, &session.stream_id, NULL) == 0) {
            size_t stream_offset = 0;
            int stream_fin_sent = 0;

            while (now_ns() < deadline) {
                if (doq_ngtcp2_send_stream_data(
                        &session,
                        fd,
                        stream_data,
                        stream_data_len,
                        &stream_offset,
                        &stream_fin_sent)
                    != 0) {
                    break;
                }
                if (doq_ngtcp2_send_generated_packet(&session, fd) != 0) {
                    break;
                }

                int io_ready = doq_ngtcp2_wait_for_io(fd, deadline);
                if (io_ready < 0) {
                    break;
                }
                if (io_ready > 0 && doq_ngtcp2_receive_packets(&session, fd) != 0) {
                    break;
                }
                if (doq_ngtcp2_handle_timers(&session) != 0) {
                    break;
                }

                if (session.stream_response_ready) {
                    if (session.stream_expected_len >= 2 && session.stream_rx_len == session.stream_expected_len) {
                        size_t dns_len = session.stream_expected_len - 2;
                        uint8_t *dns_resp = (uint8_t *)malloc(dns_len);
                        if (dns_resp != NULL) {
                            memcpy(dns_resp, session.stream_rx + 2, dns_len);
                            *response_out = dns_resp;
                            *response_len_out = dns_len;
                            result = 0;
                        }
                    }
                    break;
                }
            }
        }
    }

    doq_ngtcp2_session_cleanup(&session);
    close(fd);

    return result;
}

#endif
