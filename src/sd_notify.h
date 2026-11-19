#ifndef SD_NOTIFY_H
#define SD_NOTIFY_H

#include <stddef.h>

#include "errors.h"

/*
 * systemd readiness notification (Type=notify) without libsystemd.
 *
 * The protocol is a single datagram of newline-separated KEY=VALUE pairs
 * sent to the AF_UNIX socket named by $NOTIFY_SOCKET (a filesystem path, or
 * an abstract name when it starts with '@'). Linking libsystemd for one
 * sendto() would add a dependency the Alpine image does not otherwise need.
 *
 * sd_notify_init() resolves the address and opens the socket once, so that
 * sd_notify_send_signal_safe() can run inside a signal handler: it does
 * nothing but sendto() on state prepared beforehand. When $NOTIFY_SOCKET is
 * unset every call is a successful no-op, which is the normal case outside
 * systemd (Docker, tests, a shell).
 */

/* Read $NOTIFY_SOCKET and open the notification socket. PROXY_OK when unset.
 * PROXY_ERR_CONFIG for an address this implementation cannot use (vsock,
 * relative path, too long); PROXY_ERR_NETWORK when socket() fails. */
proxy_status_t sd_notify_init(void);

/* 1 when init found a usable $NOTIFY_SOCKET. */
int sd_notify_enabled(void);

/* Send one state datagram, e.g. "READY=1\nSTATUS=listening". No-op when
 * disabled. PROXY_ERR_NETWORK if sendto() fails. */
proxy_status_t sd_notify_send(const char *state);

/* Async-signal-safe send for use in a handler; errors are dropped because
 * there is nothing a handler could do with them. */
void sd_notify_send_signal_safe(const char *state, size_t len);

/* Close the socket and return to the disabled state. */
void sd_notify_close(void);

#endif
