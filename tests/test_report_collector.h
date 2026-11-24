#ifndef TEST_REPORT_COLLECTOR_H
#define TEST_REPORT_COLLECTOR_H

/*
 * A stand-in for the router's report collector: a bound AF_UNIX datagram
 * socket in a private temp directory. Include it before any test macro that
 * wraps socket calls, so it talks to the real kernel.
 *
 * Needs cmocka.h included first.
 */

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "report.h"

typedef struct {
    char dir[64];
    char path[96];
    int fd;
} test_collector_t;

/* Binds the socket. With open_sink set, also points the proxy's report sink
 * at it. */
static inline void test_collector_open(test_collector_t *c, int open_sink) {
    snprintf(c->dir, sizeof(c->dir), "/tmp/dnsproxy_report_XXXXXX");
    assert_non_null(mkdtemp(c->dir));
    snprintf(c->path, sizeof(c->path), "%s/ingest.sock", c->dir);
    c->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    assert_true(c->fd >= 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, c->path, strlen(c->path) + 1);
    assert_int_equal(bind(c->fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    if (open_sink) {
        assert_int_equal(report_open(c->path), PROXY_OK);
    }
}

/* Closes the sink as well, whether or not this collector opened it. */
static inline void test_collector_close(test_collector_t *c) {
    report_close();
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    unlink(c->path);
    rmdir(c->dir);
}

static inline int test_collector_recv(test_collector_t *c, char *buf, size_t cap, int timeout_ms) {
    struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
    if (poll(&pfd, 1, timeout_ms) != 1) {
        return -1;
    }
    ssize_t n = recv(c->fd, buf, cap - 1, 0);
    if (n < 0) {
        return -1;
    }
    buf[n] = '\0';
    return (int)n;
}

static inline void test_collector_expect(test_collector_t *c, char *buf, size_t cap) {
    assert_true(test_collector_recv(c, buf, cap, 1000) > 0);
}

static inline int test_collector_pending(test_collector_t *c) {
    struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
    return poll(&pfd, 1, 0) == 1;
}

#endif
