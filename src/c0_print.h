#ifndef C0_PRINT_H
#define C0_PRINT_H
#include <stdarg.h> // va_list

#include "c0_types.h"

typedef u32 C0PrinterFlags;

typedef struct C0Proc C0Proc;
typedef struct C0Gen C0Gen;

enum C0PrinterFlag_enum {
	C0PrinterFlag_UseInlineArgs = 1u << 0u,
};

typedef struct C0Printer C0Printer;
struct C0Printer {
	C0PrinterFlags flags;

	void (*custom_vprintf)(C0Printer *p, char const *fmt, va_list va);
	void *user_data;
};

void c0_print_proc(C0Printer *p, C0Proc *procedure);
void c0_gen_instructions_print(C0Printer *p, C0Gen *gen);

#endif // C0_PRINT_H