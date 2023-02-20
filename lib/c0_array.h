#ifndef C0_ARRAY_H
#define C0_ARRAY_H

#include <string.h> // memmove

#include "c0_types.h"

typedef struct C0Array C0Array;

struct C0Array {
	// alignas(2*sizeof(isize))
	usize len;
	usize cap;
};

#define C0Array(T) T *

#define c0_array_meta(array) \
	(&((C0Array*)(array))[-1])

#define c0_array_len(array) \
	((array) ? c0_array_meta(array)->len : 0)

#define c0_array_cap(array) \
	((array) ? c0_array_meta(array)->cap : 0)

#define c0_array_try_grow(array, size) \
	(((array) && c0_array_meta(array)->len + (size) < c0_array_meta(array)->cap) \
		? true \
		: c0_array_grow_((void **)&(array), (size), sizeof(*(array))))

#define c0_array_expand(array, size) \
	(c0_array_try_grow((array), (size)) \
		? (c0_array_meta(array)->len += (size), true) \
		: false)

#define c0_array_push(array, value) \
	(c0_array_try_grow((array), 1) \
		? ((array)[c0_array_meta(array)->len++] = (value), true) \
		: false)

#define c0_array_pop(array) \
	(c0_array_len(array) > 0 \
		? (--c0_array_meta(array)->len) \
		: 0)

#define c0_array_free(array) \
	(void)((array) ? (c0_array_delete(array), (array) = 0) : 0)

#define c0_array_insert(array, index, value) \
	(c0_array_expand(array, 1) \
		? (memmove(&(array)[(index)+1], &(array)[index], (c0_array_len(array) - (index) - 1) * sizeof(*(array))), (array)[index] = (value), true) \
		: false)

#define c0_array_ordered_remove(array, index) do { \
	C0_ASSERT(index < c0_array_len(array)); \
	memmove(&(array)[index], &(array)[(index)+1], (c0_array_len(array) - (index)-1) * sizeof(*(array))); \
	c0_array_meta(array)->len -= 1; \
} while (0)

#define c0_array_resize(array, size) \
	((array) \
		? (c0_array_meta(array)->len >= (size) \
			? (c0_array_meta(array)->len = (size), true) \
			: c0_array_expand((array), (size) - c0_array_meta(array)->len)) \
		: (c0_array_grow_((void **)&(array), (size), sizeof(*(array))) \
			? (c0_array_meta(array)->len = (size), true) \
			: false))

#define c0_array_last(array) \
	((array)[c0_array_len(array) - 1])

#define c0_array_clear(array) \
	(void)((array) ? c0_array_meta(array)->len = 0 : 0)

bool c0_array_grow_(void **const array, usize elements, usize type_size);
void c0_array_delete(void *const array);

#endif // C0_ARRAY_H