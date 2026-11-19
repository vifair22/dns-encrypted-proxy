#define _POSIX_C_SOURCE 200809L

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "errors.h"
#include "sd_notify.h"

/*
 * Stand-in for systemd's notification socket: bind a datagram socket, point
 * NOTIFY_SOCKET at it, and read back what the proxy sent.
 */
typedef struct {
    int fd;
    char path[108];
} fake_systemd_t;

static int fake_systemd_open_path(fake_systemd_t *fs) {
    snprintf(fs->path, sizeof(fs->path), "/tmp/dnsproxy-notify-%ld.sock", (long)getpid());
    unlink(fs->path);
    fs->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fs->fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, fs->path, strlen(fs->path));
    if (bind(fs->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fs->fd);
        return -1;
    }
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fs->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

/* Abstract socket: name given to NOTIFY_SOCKET as "@name", bound with a
 * leading NUL and a length that covers only the name bytes. */
static int fake_systemd_open_abstract(fake_systemd_t *fs) {
    snprintf(fs->path, sizeof(fs->path), "@dnsproxy-notify-%ld", (long)getpid());
    fs->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fs->fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t len = strlen(fs->path);
    memcpy(addr.sun_path, fs->path, len);
    addr.sun_path[0] = '\0';
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
    if (bind(fs->fd, (struct sockaddr *)&addr, alen) != 0) {
        close(fs->fd);
        return -1;
    }
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(fs->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

static void fake_systemd_close(fake_systemd_t *fs) {
    close(fs->fd);
    if (fs->path[0] == '/') {
        unlink(fs->path);
    }
}

static ssize_t fake_systemd_recv(fake_systemd_t *fs, char *buf, size_t cap) {
    ssize_t n = recv(fs->fd, buf, cap - 1, 0);
    if (n >= 0) {
        buf[n] = '\0';
    }
    return n;
}

static int teardown(void **state) {
    (void)state;
    sd_notify_close();
    unsetenv("NOTIFY_SOCKET");
    return 0;
}

static void test_unset_is_noop(void **state) {
    (void)state;
    unsetenv("NOTIFY_SOCKET");
    assert_int_equal(sd_notify_init(), PROXY_OK);
    assert_int_equal(sd_notify_enabled(), 0);
    assert_int_equal(sd_notify_send("READY=1"), PROXY_OK);
    sd_notify_send_signal_safe("STOPPING=1", 10);

    setenv("NOTIFY_SOCKET", "", 1);
    assert_int_equal(sd_notify_init(), PROXY_OK);
    assert_int_equal(sd_notify_enabled(), 0);
}

static void test_path_socket_receives_states(void **state) {
    (void)state;
    fake_systemd_t fs;
    assert_int_equal(fake_systemd_open_path(&fs), 0);
    setenv("NOTIFY_SOCKET", fs.path, 1);

    assert_int_equal(sd_notify_init(), PROXY_OK);
    assert_int_equal(sd_notify_enabled(), 1);

    char buf[256];
    assert_int_equal(sd_notify_send("READY=1\nSTATUS=Serving"), PROXY_OK);
    assert_true(fake_systemd_recv(&fs, buf, sizeof(buf)) > 0);
    assert_string_equal(buf, "READY=1\nSTATUS=Serving");

    sd_notify_send_signal_safe("STOPPING=1", 10);
    assert_true(fake_systemd_recv(&fs, buf, sizeof(buf)) > 0);
    assert_string_equal(buf, "STOPPING=1");

    sd_notify_close();
    assert_int_equal(sd_notify_enabled(), 0);
    fake_systemd_close(&fs);
}

static void test_abstract_socket_receives_states(void **state) {
    (void)state;
    fake_systemd_t fs;
    assert_int_equal(fake_systemd_open_abstract(&fs), 0);
    setenv("NOTIFY_SOCKET", fs.path, 1);

    assert_int_equal(sd_notify_init(), PROXY_OK);
    char buf[256];
    assert_int_equal(sd_notify_send("READY=1"), PROXY_OK);
    assert_true(fake_systemd_recv(&fs, buf, sizeof(buf)) > 0);
    assert_string_equal(buf, "READY=1");
    fake_systemd_close(&fs);
}

static void test_rejects_unusable_addresses(void **state) {
    (void)state;
    setenv("NOTIFY_SOCKET", "vsock:2:1234", 1);
    assert_int_equal(sd_notify_init(), PROXY_ERR_CONFIG);
    assert_non_null(strstr(proxy_error_message(), "NOTIFY_SOCKET"));
    assert_int_equal(sd_notify_enabled(), 0);

    setenv("NOTIFY_SOCKET", "relative/notify.sock", 1);
    assert_int_equal(sd_notify_init(), PROXY_ERR_CONFIG);

    char long_path[200];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';
    setenv("NOTIFY_SOCKET", long_path, 1);
    assert_int_equal(sd_notify_init(), PROXY_ERR_CONFIG);
    assert_int_equal(sd_notify_enabled(), 0);
}

static void test_send_reports_missing_listener(void **state) {
    (void)state;
    /* systemd gone (or the socket never existed): sendto fails with
     * ENOENT/ECONNREFUSED and the caller gets a network error to log. */
    setenv("NOTIFY_SOCKET", "/tmp/dnsproxy-notify-does-not-exist.sock", 1);
    assert_int_equal(sd_notify_init(), PROXY_OK);
    assert_int_equal(sd_notify_send("READY=1"), PROXY_ERR_NETWORK);
    assert_int_equal(sd_notify_send(NULL), PROXY_ERR_INVALID_ARG);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_unset_is_noop, teardown),
        cmocka_unit_test_teardown(test_path_socket_receives_states, teardown),
        cmocka_unit_test_teardown(test_abstract_socket_receives_states, teardown),
        cmocka_unit_test_teardown(test_rejects_unusable_addresses, teardown),
        cmocka_unit_test_teardown(test_send_reports_missing_listener, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
