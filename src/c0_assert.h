#ifndef C0_ASSERT_H
#define C0_ASSERT_H

#include "c0_types.h"

C0_NORETURN void c0_assert_fail(const char *expression, const C0SourceLocation *location);

#define C0_ASSERT(expression) \
	((void)((expression) ? (void)0 : c0_assert_fail(#expression, C0_SOURCE_LOCATION)))

#endif // C0_ASSERT_H