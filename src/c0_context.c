
#include <stdio.h> // fprintf
#include <string.h> // memset

#include "c0_context.h"

_Thread_local C0Context c0_context;

static void assert_cb(char const *file, char const *function, int line, char const *condition, char const *fmt, va_list va) {
#if defined(_MSC_VER)
	fprintf(stderr, "%s(%d): %s: %s", file, line, function, condition);
#else
	fprintf(stderr, "%s:%d: %s: %s", file, line, function, condition);
#endif
	if (fmt) {
		vfprintf(stderr, fmt, va);
	}
	fprintf(stderr, "\n");
}

const C0Context C0_DEFAULT_CONTEXT = {
	assert_cb,
	&C0_STDLIB_ALLOCATOR,
	&C0_STDLIB_LOGGER,
};

void *c0_allocate_uninitialized(usize bytes) {
	const C0Allocator *allocator = c0_context.allocator;
	return allocator->allocate(allocator->user, bytes);
}

void *c0_reallocate(void *data, usize bytes) {
	const C0Allocator *allocator = c0_context.allocator;
	return allocator->reallocate(allocator->user, data, bytes);
}

void c0_deallocate(void *data) {
	const C0Allocator *allocator = c0_context.allocator;
	return allocator->deallocate(allocator->user, data);
}

void c0_deallocate_all(void) {
	const C0Allocator *allocator = c0_context.allocator;
	allocator->deallocate_all(allocator->user);
}

void *c0_allocate_zeroed(usize bytes) {
	void *data = c0_allocate_uninitialized(bytes);
	if (data) {
		memset(data, 0, bytes);
		return data;
	}
	return 0;
}