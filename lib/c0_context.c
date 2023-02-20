#include <string.h> // memset

#include "c0_context.h"

#include "c0_allocator.h" // C0_STDLIB_ALLOCATOR
#include "c0_logger.h" // C0_STDIO_LOGGER

C0_THREAD_LOCAL C0Context c0_context;

const C0Context C0_DEFAULT_CONTEXT = {
	&C0_STDLIB_ALLOCATOR,
	&C0_STDIO_LOGGER,
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