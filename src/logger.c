#define _POSIX_C_SOURCE 200809L

#include "logger.h"

#include <log.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static int g_logger_min_level = 1; /* INFO */

static int logger_level_value(const char *level) {
    if (level == NULL) {
        return 1;
    }
    if (strcasecmp(level, "DEBUG") == 0) {
        return 0;
    }
    if (strcasecmp(level, "INFO") == 0) {
        return 1;
    }
    if (strcasecmp(level, "WARN") == 0) {
        return 2;
    }
    if (strcasecmp(level, "ERROR") == 0) {
        return 3;
    }
    return 1;
}

void logger_set_level(const char *level) {
    g_logger_min_level = logger_level_value(level);
}

void logger_logf(const char *func, const char *level, const char *fmt, ...) {
    if (func == NULL || level == NULL || fmt == NULL) {
        return;
    }

    if (logger_level_value(level) < g_logger_min_level) {
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
