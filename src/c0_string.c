#include <string.h> // memcpy

#include "c0_string.h"
#include "c0_context.h"

C0String c0_string_copy(C0String string) {
	char *data = c0_allocate_uninitialized(string.len);
	memcpy(data, string.text, string.len);
	return C0_LIT(C0String, data, string.len);
}