#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include <stdio.h>
#include <log.h>

static inline void logger_logf(const char *func, const char *level, const char *fmt, ...) {
    if (func == NULL || level == NULL || fmt == NULL) {
        return;
    }

    char buffer[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }

    log_msg_impl(buffer, level, func);
}

#define LOGF_DEBUG(...) logger_logf(__func__, "DEBUG", __VA_ARGS__)
#define LOGF_INFO(...) logger_logf(__func__, "INFO", __VA_ARGS__)
#define LOGF_WARN(...) logger_logf(__func__, "WARN", __VA_ARGS__)
#define LOGF_ERROR(...) logger_logf(__func__, "ERROR", __VA_ARGS__)

#endif
