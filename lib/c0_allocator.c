#include <stdlib.h> // malloc, realloc, free
#include <stddef.h> // max_align_t
#include <string.h> // memcpy

#include "c0_assert.h"
#include "c0_config.h"
#include "c0_allocator.h"

static void* allocate_stdlib(void *user, usize bytes) {
	(void)user;
	return malloc(bytes);
}

static void* reallocate_stdlib(void *user, void *data, usize bytes) {
	(void)user;
	return realloc(data, bytes);
}

static void deallocate_stdlib(void *user, void *data) {
	(void)user;
	free(data);
}

static void deallocate_all_stdlib(void *user) {
	(void)user;
	// Does nothing.
}

const C0Allocator C0_STDLIB_ALLOCATOR = {
	0,
	allocate_stdlib,
	reallocate_stdlib,
	deallocate_stdlib,
	deallocate_all_stdlib,
};

// Custom arena allocator
#define MINIMUM_BLOCK_SIZE (8ll*1024ll*1024ll)

typedef struct Arena Arena;
typedef struct Block Block;

struct Block {
	Block *prev;
	u8 *base;
	usize size;
	usize used;
};

struct Arena {
	const C0Allocator *base;
	Block *block;
};

static inline usize align_formula(usize size, usize align) {
	const usize result = size + align-1;
	return result - result%align;
}

static usize arena_align_forward_offset(Arena *arena, usize alignment) {
	const usize ptr = (usize)(arena->block->base + arena->block->used);
	const usize mask = alignment-1;
	return (ptr & mask) ? alignment - (ptr & mask) : 0;
}

static void *arena_allocate(Arena *arena, usize min_size, usize alignment) {
	min_size += sizeof(usize);

	usize size = 0;
	if (arena->block) {
		size = min_size + arena_align_forward_offset(arena, alignment);
	}

	if (!arena->block || (arena->block->used + size) > arena->block->size) {
		size = align_formula(min_size, alignment);

		usize block_size = size;
		if (block_size < MINIMUM_BLOCK_SIZE) {
			block_size = MINIMUM_BLOCK_SIZE;
		}

		Block *new_block = (Block *)arena->base->allocate(arena->base->user, block_size);
		if (!new_block) {
			return 0;
		}
		new_block->used = 0;
		new_block->size = block_size;
		new_block->base = (u8 *)new_block + sizeof(Block);
		new_block->prev = arena->block;
		arena->block = new_block;
	}

	Block *block = arena->block;
	C0_ASSERT((block->used + size) <= block->size);

	u8 *data = block->base + block->used;
	data += arena_align_forward_offset(arena, alignment);

	block->used += size;
	C0_ASSERT(block->used <= block->size);

	((usize*)data)[0] = size;

	return data + sizeof(usize);
}

static void arena_deallocate_all(Arena *arena) {
	while (arena->block != NULL) {
		Block *block = arena->block;
		arena->block = block->prev;
		arena->base->deallocate(arena->base->user, block);
	}
}

static void *allocate_arena(void *user, usize bytes) {
	return arena_allocate((Arena *)user, bytes, C0_ALIGNOF(max_align_t));
}

static void *reallocate_arena(void *user, void *data, usize bytes) {
	void *resize = allocate_arena((Arena *)user, bytes);
	if (data) {
		usize size = ((usize*)data)[-1];
		memcpy(resize, data, size);
	}
	return resize;
}

static void deallocate_arena(void *user, void *data) {
	(void)user;
	(void)data;
	// Do nothing.
}

static void deallocate_all_arena(void *user) {
	arena_deallocate_all((Arena *)user);
}

C0Allocator c0_arena_create(const C0Allocator *allocator) {
	Arena *arena = (Arena *)allocator->allocate(allocator->user, sizeof(Arena));
	arena->base = allocator;
	arena->block = 0;

	C0Allocator result;
	result.user = arena;
	result.allocate = allocate_arena;
	result.reallocate = reallocate_arena;
	result.deallocate = deallocate_arena;
	result.deallocate_all = deallocate_all_arena;

	return result;
}

void c0_arena_destroy(const C0Allocator *allocator) {
	deallocate_all_arena(allocator->user);
	Arena *arena = (Arena *)allocator->user;
	const C0Allocator *base = arena->base;
	base->deallocate(base->user, arena);
}