#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

void logger_set_level(const char *level);
void logger_logf(const char *func, const char *level, const char *fmt, ...);

#define LOGF_DEBUG(...) logger_logf(__func__, "DEBUG", __VA_ARGS__)
#define LOGF_INFO(...) logger_logf(__func__, "INFO", __VA_ARGS__)
#define LOGF_WARN(...) logger_logf(__func__, "WARN", __VA_ARGS__)
#define LOGF_ERROR(...) logger_logf(__func__, "ERROR", __VA_ARGS__)

#endif
