#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if !defined(_WIN32)
typedef void *HANDLE;
struct tm;
struct tm *localtime_r(const time_t *timer, struct tm *result);
void flockfile(FILE *stream);
void funlockfile(FILE *stream);
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtrigraphs"
#endif
#include <log.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static inline void logger_logf(const char *level, const char *fmt, ...) {
    if (level == NULL || fmt == NULL) {
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

    log_msg(level, buffer);
}

#define LOGF_DEBUG(...) logger_logf("DEBUG", __VA_ARGS__)
#define LOGF_INFO(...) logger_logf("INFO", __VA_ARGS__)
#define LOGF_WARN(...) logger_logf("WARN", __VA_ARGS__)
#define LOGF_ERROR(...) logger_logf("ERROR", __VA_ARGS__)

#endif
