#ifndef C0_STRING_H
#define C0_STRING_H

#include "c0_types.h"

typedef struct C0String C0String;

struct C0String {
	char const *text;
	usize len;
};

// C0String s = C0STR("Hellope");
#ifndef C0STR
# define C0STR(lit) C0_LIT(C0String, (lit), sizeof(lit) - 1)
#endif

// printf("%.*s", C0PSTR(s));
#ifndef C0PSTR
#define C0PSTR(s) (int)(s).len, (s).text
#endif

C0String c0_string_copy(C0String string);

#endif // C0_STRING_H