#include <string.h> // memcpy, memcmp

#include "c0_string.h"
#include "c0_allocator.h"

C0String c0_string_copy(C0String string) {
	char *data = (char *)c0_allocate_uninitialized(string.len);
	memcpy(data, string.text, string.len);
	return C0_LIT(C0String, data, string.len);
}

bool c0_string_compare(C0String lhs, C0String rhs) {
	if (lhs.text == rhs.text) {
		return true;
	}
	if (lhs.len != rhs.len) {
		return false;
	}
	return memcmp(lhs.text, rhs.text, lhs.len) == 0;
}