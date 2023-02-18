#include <stdio.h> // fputs, vfprintf, std{out,err}
#include <stdarg.h> // va_list, va_{start,end}

#include "c0_logger.h"
#include "c0_context.h"

static void callback(void *user, const C0SourceLocation *location, int level, char const *fmt, va_list va) {
	switch (level) {
	case C0_LOG_INFO:
		fputs("INFO: ", stdout);
		vfprintf(stdout, fmt, va);
		fputs("\n", stdout);
		break;
	case C0_LOG_WARNING:
		fputs("WARNING: ", stderr);
		vfprintf(stderr, fmt, va);
		fputs("\n", stderr);
		break;
	case C0_LOG_ERROR:
		fputs("ERROR: ", stderr);
		vfprintf(stderr, fmt, va);
		fputs("\n", stderr);
		break;
	}
}

void c0_log(const C0SourceLocation *location, int level, const char *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	const C0Logger *logger = c0_context.logger;
	logger->callback(logger->user, location, level, fmt, va);
	va_end(va);
}

const C0Logger C0_STDIO_LOGGER = {
	0,
	callback,
};