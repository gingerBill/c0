#include <stdio.h> // fputs, vfprintf, std{out,err}

#include "c0_logger.h"

static void log_proc(const C0SourceLocation *location, int level, char const *fmt, va_list va) {
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

const C0Logger C0_STDLIB_LOGGER = {
	log_proc,
};