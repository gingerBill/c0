#ifndef C0_BACKEND_H
#define C0_BACKEND_H

#include "c0_array.h"
#include "c0_string.h"

typedef struct C0Gen C0Gen;
typedef struct C0Backend C0Backend;

struct C0Backend {
	C0String name;
	C0Array(u8) (*emit)(const C0Gen *gen);
};

C0Array(u8) c0_emit(const C0Gen *gen, C0String name);

#endif // C0_BACKEND_H