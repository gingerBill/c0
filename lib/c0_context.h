#ifndef C0_CONTEXT_H
#define C0_CONTEXT_H
#include "c0_types.h"

typedef struct C0Allocator C0Allocator;
typedef struct C0Logger C0Logger;
typedef struct C0Context C0Context;

struct C0Context {
	const C0Allocator *allocator;
	const C0Logger *logger;
};

extern const C0Context C0_DEFAULT_CONTEXT;

extern C0_THREAD_LOCAL C0Context c0_context;

#endif // C0_CONTEXT_H