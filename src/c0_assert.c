#include <stdlib.h> // abort

#include "c0_assert.h"
#include "c0_logger.h"

C0_NORETURN void c0_assert_fail(const char *expression, const C0SourceLocation *location) {
#if defined(_MSC_VER)
	c0_error("Assertion Failed: %s(%d): %s: %s", location->file, location->line, location->function, expression);
#else
	c0_error("Assertion Failed: %s:%d %s: %s", location->file, location->line, location->function, expression);
#endif
	abort();
}