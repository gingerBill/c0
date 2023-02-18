#ifndef C0_LOGGER_H
#define C0_LOGGER_H

#include <stdarg.h> // va_list

#include "c0_config.h"

#define C0_LOG_INFO    0
#define C0_LOG_WARNING 1
#define C0_LOG_ERROR   2

typedef struct C0Logger C0Logger;
typedef struct C0SourceLocation C0SourceLocation;

struct C0Logger {
	void *user;
	void (*callback)(void *user, const C0SourceLocation *location, int level, const char *fmt, va_list va);
};

void c0_log(const C0SourceLocation *location, int level, const char *fmt, ...);

#define c0_info(...) \
	c0_log(&C0_SOURCE_LOCATION, C0_LOG_INFO, __VA_ARGS__)

#define c0_warning(...) \
	c0_log(&C0_SOURCE_LOCATION, C0_LOG_WARNING, __VA_ARGS__)

#define c0_error(...) \
	c0_log(&C0_SOURCE_LOCATION, C0_LOG_ERROR, __VA_ARGS__)

extern const C0Logger C0_STDIO_LOGGER;

#endif // C0_LOGGER_H