#include "c0_backend.h"

extern const C0Backend C0_BACKEND_C;
extern const C0Backend C0_BACKEND_ASM;

C0Array(u8) c0_emit(const C0Gen *gen, C0String name) {
	if (c0_string_compare(name, C0_SLIT("C"))) {
		return C0_BACKEND_C.emit(gen);
	}
	if (c0_string_compare(name, C0_SLIT("ASM"))) {
		return C0_BACKEND_ASM.emit(gen);
	}
	return 0;
}