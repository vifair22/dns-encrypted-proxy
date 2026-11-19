#define _POSIX_C_SOURCE 200809L

#include "sd_notify.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* Written only by init/close, which main runs single-threaded before and
 * after everything else; handlers and worker threads only read them. */
static int g_notify_fd = -1;
static struct sockaddr_un g_notify_addr;
static socklen_t g_notify_addr_len = 0;

proxy_status_t sd_notify_init(void) {
    sd_notify_close();

    const char *name = getenv("NOTIFY_SOCKET");
    if (name == NULL || name[0] == '\0') {
        return PROXY_OK;
    }

    if (name[0] != '/' && name[0] != '@') {
        return set_error(PROXY_ERR_CONFIG,
                         "NOTIFY_SOCKET must be an absolute path or an @abstract name (got '%s')",
                         name);
    }

    size_t len = strlen(name);
    if (len >= sizeof(g_notify_addr.sun_path)) {
        return set_error(PROXY_ERR_CONFIG,
                         "NOTIFY_SOCKET is %zu bytes, longer than sun_path allows (%zu)",
                         len, sizeof(g_notify_addr.sun_path) - 1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name, len);
    if (addr.sun_path[0] == '@') {
        /* Abstract namespace: leading NUL, and the length counts exactly the
         * name bytes, since trailing NULs would be part of the name. */
        addr.sun_path[0] = '\0';
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return set_error_errno(PROXY_ERR_NETWORK, "socket(AF_UNIX, SOCK_DGRAM) for NOTIFY_SOCKET");
    }
    /* Not inherited by anything this process might exec. */
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);

    g_notify_addr = addr;
    g_notify_addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
    g_notify_fd = fd;
    return PROXY_OK;
}

int sd_notify_enabled(void) {
    return g_notify_fd >= 0;
}

proxy_status_t sd_notify_send(const char *state) {
    if (state == NULL) {
        return set_error(PROXY_ERR_INVALID_ARG, "state=NULL");
    }
    if (g_notify_fd < 0) {
        return PROXY_OK;
    }

    size_t len = strlen(state);
    ssize_t sent = sendto(g_notify_fd, state, len, MSG_NOSIGNAL,
                          (const struct sockaddr *)&g_notify_addr, g_notify_addr_len);
    if (sent < 0) {
        return set_error_errno(PROXY_ERR_NETWORK, "sendto NOTIFY_SOCKET");
    }
    if ((size_t)sent != len) {
        return set_error(PROXY_ERR_NETWORK,
                         "short send to NOTIFY_SOCKET (%zd of %zu bytes)",
                         sent, len);
    }
    return PROXY_OK;
}

void sd_notify_send_signal_safe(const char *state, size_t len) {
    if (g_notify_fd < 0 || state == NULL) {
        return;
    }
    (void)sendto(g_notify_fd, state, len, MSG_NOSIGNAL,
                 (const struct sockaddr *)&g_notify_addr, g_notify_addr_len);
}

void sd_notify_close(void) {
    if (g_notify_fd >= 0) {
        close(g_notify_fd);
    }
    g_notify_fd = -1;
    g_notify_addr_len = 0;
    memset(&g_notify_addr, 0, sizeof(g_notify_addr));
}
