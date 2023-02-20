#ifndef C0_STRING_H
#define C0_STRING_H

#include "c0_types.h"

typedef struct C0String C0String;

struct C0String {
	const char *text;
	usize len;
};

// C0String s = C0_SLIT("Hellope");
#ifndef C0_SLIT
#	define C0_SLIT(lit) C0_LIT(C0String, (lit), sizeof(lit) - 1)
#endif

// printf("%.*s", C0_SFMT(s));
#ifndef C0_SFMT
#	define C0_SFMT(s) (int)(s).len, (s).text
#endif

C0String c0_string_copy(C0String string);
bool c0_string_compare(C0String lhs, C0String rhs);

#endif // C0_STRING_H