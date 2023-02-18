#ifndef C0_TYPES_H
#define C0_TYPES_H

#include "c0_config.h"

#include <stddef.h> // ptrdiff_t, size_t
#include <stdbool.h> // bool, true, false

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef size_t usize;

typedef signed char i8;
typedef signed short i16;
typedef signed int i32;
typedef ptrdiff_t isize;

typedef float f32;
typedef double f64;

#if defined(C0_PLATFORM_WINDOWS)
// Windows is LLP64
typedef unsigned long long u64;
typedef signed long long i64;
#elif defined(C0_PLATFORM_LINUX)
// Linux is LP64
typedef unsigned long u64;
typedef signed long i64;
#endif

typedef struct C0SourceLocation C0SourceLocation;

struct C0SourceLocation {
	const char *file;
	const char *function;
	int line;
};

#define C0_SOURCE_LOCATION \
	C0_LIT(const C0SourceLocation, __FILE__, __func__, __LINE__)

#endif // C0_TYPES_H