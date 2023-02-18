#ifndef C0_ALLOCATOR_H
#define C0_ALLOCATOR_H

#include "c0_types.h" // usize

typedef struct C0Allocator C0Allocator;

struct C0Allocator {
	void *user;
	void* (*allocate)(void *user, usize bytes);
	void* (*reallocate)(void *user, void *data, usize bytes);
	void (*deallocate)(void *user, void *data);
	void (*deallocate_all)(void *user);
};

extern const C0Allocator C0_STDLIB_ALLOCATOR;

C0Allocator c0_arena_create(const C0Allocator *allocator);
void c0_arena_destroy(const C0Allocator *allocator);

#endif // C0_ALLOCATOR_H