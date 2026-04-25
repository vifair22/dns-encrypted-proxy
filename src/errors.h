#ifndef ERRORS_H
#define ERRORS_H

#include <errno.h>

/*
 * Project-wide error reporting.
 *
 * The deepest function in a failure path records a code + human-readable
 * message via set_error(). Callers propagate the code unchanged; they do
 * not overwrite the message. The CLI/main layer reads proxy_error_message()
 * to surface the failure (typically into LOGF_ERROR).
 */

typedef enum {
    PROXY_OK              =  0,
    PROXY_ERR_INVALID_ARG = -1,  /* null pointer / out-of-range */
    PROXY_ERR_CONFIG      = -2,  /* config file / env var / parse */
    PROXY_ERR_NETWORK     = -3,  /* socket / connect / bind / send / recv */
    PROXY_ERR_PROTOCOL    = -4,  /* DNS / DoH / DoT / DoQ wire-format */
    PROXY_ERR_TIMEOUT     = -5,  /* deadline exceeded */
    PROXY_ERR_RESOURCE    = -6,  /* OOM / fd exhaustion / queue full */
    PROXY_ERR_INTERNAL    = -7   /* invariant violated */
} proxy_status_t;

/*
 * The macros snapshot __func__ (and errno, for the _errno variant) at the
 * call site before invoking the impl. set_error_errno captures errno before
 * vsnprintf can clobber it.
 *
 * Both macros return the status code so call sites can chain:
 *     return set_error(PROXY_ERR_CONFIG, "missing key %s", key);
 */
#define set_error(code, ...) \
    proxy_set_error_impl((code), __func__, __VA_ARGS__)
#define set_error_errno(code, ...) \
    proxy_set_error_errno_impl((code), errno, __func__, __VA_ARGS__)

proxy_status_t proxy_set_error_impl(proxy_status_t code,
                                    const char *func,
                                    const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

proxy_status_t proxy_set_error_errno_impl(proxy_status_t code,
                                          int saved_errno,
                                          const char *func,
                                          const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

const char *proxy_error_message(void);
void        proxy_error_clear(void);
const char *proxy_status_name(proxy_status_t code);

#endif
