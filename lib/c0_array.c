#include "c0_array.h"
#include "c0_allocator.h"

bool c0_array_grow_(void **const array, usize elements, usize type_size) {
	usize count = 0;
	void *data = 0;
	if (*array) {
		C0Array *const meta = c0_array_meta(*array);
		count = 2 * meta->cap + elements;

		data = c0_reallocate(meta, type_size * count + sizeof(*meta));
		if (!data) {
			c0_deallocate(meta);
			return false;
		}
	} else {
		count = elements + 1;
		data = c0_allocate_uninitialized(type_size * count + sizeof(C0Array));
		if (!data) {
			return false;
		}
		((C0Array *)data)->len = 0;
	}
	C0Array *meta = (C0Array *)data;
	meta->cap = count;
	*array = meta + 1;
	return true;
}

void c0_array_delete(void *const array) {
	if (array) {
		c0_deallocate(c0_array_meta(array));
	}
}
