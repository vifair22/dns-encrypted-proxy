#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700  /* select XSI strerror_r (returns int) */

#include "errors.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define PROXY_ERROR_BUFFER_SIZE 256
#define PROXY_STRERROR_BUFFER_SIZE 128

static __thread char g_err_buffer[PROXY_ERROR_BUFFER_SIZE];

static size_t format_prefix(const char *func) {
    if (func == NULL || func[0] == '\0') {
        g_err_buffer[0] = '\0';
        return 0;
    }
    int prefix = snprintf(g_err_buffer, sizeof(g_err_buffer), "%s: ", func);
    if (prefix < 0) {
        g_err_buffer[0] = '\0';
        return 0;
    }
    if ((size_t)prefix >= sizeof(g_err_buffer)) {
        return sizeof(g_err_buffer) - 1;
    }
    return (size_t)prefix;
}

static void format_payload(size_t offset, const char *fmt, va_list ap) {
    if (offset >= sizeof(g_err_buffer)) {
        return;
    }
    int n = vsnprintf(g_err_buffer + offset,
                      sizeof(g_err_buffer) - offset,
                      fmt, ap);
    if (n < 0) {
        g_err_buffer[offset] = '\0';
    }
}

proxy_status_t proxy_set_error_impl(proxy_status_t code,
                                    const char *func,
                                    const char *fmt, ...) {
    size_t offset = format_prefix(func);
    va_list ap;
    va_start(ap, fmt);
    format_payload(offset, fmt, ap);
    va_end(ap);
    return code;
}

proxy_status_t proxy_set_error_errno_impl(proxy_status_t code,
                                          int saved_errno,
                                          const char *func,
                                          const char *fmt, ...) {
    size_t offset = format_prefix(func);
    va_list ap;
    va_start(ap, fmt);
    format_payload(offset, fmt, ap);
    va_end(ap);

    /* Append ": <strerror>" if the buffer has room. */
    size_t used = strlen(g_err_buffer);
    if (used + 3 >= sizeof(g_err_buffer)) {
        return code;
    }
    char errbuf[PROXY_STRERROR_BUFFER_SIZE];
    errbuf[0] = '\0';
    int rc = strerror_r(saved_errno, errbuf, sizeof(errbuf));
    if (rc != 0 || errbuf[0] == '\0') {
        (void)snprintf(g_err_buffer + used,
                       sizeof(g_err_buffer) - used,
                       ": errno=%d", saved_errno);
    } else {
        (void)snprintf(g_err_buffer + used,
                       sizeof(g_err_buffer) - used,
                       ": %s", errbuf);
    }
    return code;
}

const char *proxy_error_message(void) {
    return g_err_buffer;
}

void proxy_error_clear(void) {
    g_err_buffer[0] = '\0';
}

const char *proxy_status_name(proxy_status_t code) {
    switch (code) {
        case PROXY_OK:              return "PROXY_OK";
        case PROXY_ERR_INVALID_ARG: return "PROXY_ERR_INVALID_ARG";
        case PROXY_ERR_CONFIG:      return "PROXY_ERR_CONFIG";
        case PROXY_ERR_NETWORK:     return "PROXY_ERR_NETWORK";
        case PROXY_ERR_PROTOCOL:    return "PROXY_ERR_PROTOCOL";
        case PROXY_ERR_TIMEOUT:     return "PROXY_ERR_TIMEOUT";
        case PROXY_ERR_RESOURCE:    return "PROXY_ERR_RESOURCE";
        case PROXY_ERR_INTERNAL:    return "PROXY_ERR_INTERNAL";
    }
    return "PROXY_ERR_UNKNOWN";
}
