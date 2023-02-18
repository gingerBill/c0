#ifndef C0_LOGGER_H
#define C0_LOGGER_H

#include <stdarg.h> // va_list

#include "c0_config.h"

#define C0_LOG_INFO    0
#define C0_LOG_WARNING 1
#define C0_LOG_ERROR   2

typedef struct C0Logger C0Logger;
typedef struct C0SourceLocation C0SourceLocation;

struct C0SourceLocation {
	const char *file;
	int line;
};

#define C0_SOURCE_LOCATION \
	C0_LIT(const C0SourceLocation, __FILE__, __LINE__)

struct C0Logger {
	void (*log)(const C0SourceLocation *location, int level, const char *fmt, va_list va);
};

extern const C0Logger C0_STDLIB_LOGGER;

#endif // C0_LOGGER_H