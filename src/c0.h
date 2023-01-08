#ifndef C0_HEADER_DEFINE
#define C0_HEADER_DEFINE

#if !defined(__cplusplus)
#include <stdalign.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t      u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;
typedef size_t    usize;

typedef int8_t       i8;
typedef int16_t     i16;
typedef int32_t     i32;
typedef int64_t     i64;
typedef ptrdiff_t isize;

typedef float       f32;
typedef double      f64;

typedef struct C0String      C0String;
typedef struct C0Array       C0Array;
typedef struct C0Arena       C0Arena;
typedef struct C0MemoryBlock C0MemoryBlock;

struct C0String {
	char const *text;
	isize       len;
};

// C0String s = C0STR("Hellope");
#ifndef C0STR
#if defined(__cplusplus)
	#define C0STR(lit) (C0String{(lit), sizeof(lit)-1})
#else
	#define C0STR(lit) ((C0String){(lit), sizeof(lit)-1})
#endif
#endif

#ifndef C0_ASSERT
#include <assert.h>
#define C0_ASSERT(cond) assert(cond)
#endif

#ifndef C0_PANIC
#define C0_PANIC(msg) C0_ASSERT(0 && msg)
#endif


// printf("%.*s", C0PSTR(s));
#ifndef C0PSTR
#define C0PSTR(s) (int)(s).len, (s).text
#endif

struct C0Array {
	alignas(2*sizeof(usize))
	usize len;
	usize cap;
};

#define C0Array(T) T *

#define c0array_meta(array) \
	(&((C0Array*)(array))[-1])


#define c0array_len(array) \
	((array) ? c0array_meta(array)->len : 0)

#define c0array_cap(array) \
	((array) ? c0array_meta(array)->cap : 0)

#define c0array_try_grow(array, size_) \
	(((array) && c0array_meta(array)->len + (size_) < c0array_meta(array)->cap) \
		? true \
		: c0array_grow_internal((void **)&(array), (size_), sizeof(*(array))))

#define c0array_expand(array, size_) \
	(c0array_try_grow((array), (size_)) \
		? (c0array_meta(array)->len += (size_), true) \
		: false)

#define c0array_push(array, value) \
	(c0array_try_grow((array), 1) \
		? ((array)[c0array_meta(array)->len++] = (value), true) \
		: false)

#define c0array_pop(array) \
	(c0array_len(array) > 0 \
		? (--c0array_meta(array)->len) \
		: 0)

#define c0array_free(array) \
	(void)((array) ? (c0array_delete(array), (array) = 0) : 0)

#define c0array_insert(array, index, value) \
	(c0array_expand(array, 1) \
		? (memmove(&(array)[index+1], &(array)[index], (c0array_len(array) - (index) - 1) * sizeof(*(array))), (array)[index] = (value), true) \
		: false)

#define c0array_ordered_remove(array, index) do { \
	assert((usize)index < c0array_len(array)); \
	memmove(&(array)[index], &(array)[index+1], (c0array_len(array) - (index)-1) * sizeof(*(array))); \
	c0array_meta(array)->len -= 1; \
} while (0)

#define c0array_resize(array, size_) \
	((array) \
		? (c0array_meta(array)->len >= (size_) \
			? (c0array_meta(array)->len = (size_), true) \
			: c0array_expand((array), (size_) - c0array_meta(array)->len)) \
		: (c0array_grow_internal((void **)&(array), (size_), sizeof(*(array))) \
			? (c0array_meta(array)->len = (size_), true) \
			: false))

#define c0array_last(array) \
	((array)[c0array_len(array) - 1])

#define c0array_clear(array) \
	(void)((array) ? c0array_meta(array)->len = 0 : 0)

bool c0array_grow_internal(void **const array, usize elements, usize type_size);
void c0array_delete(void *const array);

struct C0MemoryBlock {
	C0MemoryBlock *prev;
	u8 *           base;
	usize          size;
	usize          used;
};

struct C0Arena {
	C0MemoryBlock *curr_block;
	usize minimum_block_size;
	// TODO(bill): use an arena here
};


void *c0_arena_alloc   (C0Arena *arena, usize min_size, usize alignment);
void  c0_arena_free_all(C0Arena *arena);

#ifndef c0_arena_new
#define c0_arena_new(arena, T) (T *)c0_arena_alloc((arena), sizeof(T), alignof(T))
#endif

#ifndef c0_arena_new
#define c0_arena_alloc_array(arena, T, len) (T *)c0_arena_alloc((arena), sizeof(T)*(len), alignof(T))
#endif

C0String    c0_arena_str_dup (C0Arena *arena, C0String str);
char const *c0_arena_cstr_dup(C0Arena *arena, char const *str);


///////


typedef struct C0Gen     C0Gen;
typedef struct C0Instr   C0Instr;
typedef struct C0Proc    C0Proc;
typedef struct C0AggType C0AggType;
typedef struct C0Loc     C0Loc;

#define C0_BASIC_TABLE \
	C0_BASIC(void, "void",     0),  \
	C0_BASIC(i8,   "i8",       1),  \
	C0_BASIC(u8,   "u8",       1),  \
	C0_BASIC(i16,  "i16",      2),  \
	C0_BASIC(u16,  "u16",      2),  \
	C0_BASIC(i32,  "i32",      4),  \
	C0_BASIC(u32,  "u32",      4),  \
	C0_BASIC(i64,  "i64",      8),  \
	C0_BASIC(u64,  "u64",      8),  \
	C0_BASIC(i128, "i128",     16), \
	C0_BASIC(u128, "u128",     16), \
	C0_BASIC(f16,  "f16",      2),  \
	C0_BASIC(f32,  "f32",      4),  \
	C0_BASIC(f64,  "f64",      8),  \
	C0_BASIC(ptr,  "void *",  -1), /*-1 denotes that the size is `-(-1) * pointer_size`*/ \

typedef u8 C0BasicType;
enum C0BasicType_enum {
#define C0_BASIC(name, str, size) C0Basic_##name
	C0_BASIC_TABLE
#undef C0_BASIC
	C0Basic_COUNT
};

static i32 const c0_basic_type_sizes[C0Basic_COUNT] = {
#define C0_BASIC(name, str, size) size
	C0_BASIC_TABLE
#undef C0_BASIC
};

static char const *const c0_basic_names[C0Basic_COUNT] = {
#define C0_BASIC(name, str, size) str
	C0_BASIC_TABLE
#undef C0_BASIC
};


#define C0_INSTR_TABLE \
	C0_INSTR(invalid, void, 0), \
\
	C0_INSTR(load_i8,    i8,   1), \
	C0_INSTR(load_u8,    u8,   1), \
	C0_INSTR(load_i16,   i16,  1), \
	C0_INSTR(load_u16,   u16,  1), \
	C0_INSTR(load_i32,   i32,  1), \
	C0_INSTR(load_u32,   u32,  1), \
	C0_INSTR(load_i64,   i64,  1), \
	C0_INSTR(load_u64,   u64,  1), \
	C0_INSTR(load_i128,  i128, 1), \
	C0_INSTR(load_u128,  u128, 1), \
	C0_INSTR(load_f16,   f16,  1), \
	C0_INSTR(load_f32,   f32,  1), \
	C0_INSTR(load_f64,   f64,  1), \
	C0_INSTR(load_ptr,   ptr,  1), \
	C0_INSTR(store_i8,   i8,   2), \
	C0_INSTR(store_u8,   u8,   2), \
	C0_INSTR(store_i16,  i16,  2), \
	C0_INSTR(store_u16,  u16,  2), \
	C0_INSTR(store_i32,  i32,  2), \
	C0_INSTR(store_u32,  u32,  2), \
	C0_INSTR(store_i64,  i64,  2), \
	C0_INSTR(store_u64,  u64,  2), \
	C0_INSTR(store_i128, i128, 2), \
	C0_INSTR(store_u128, u128, 2), \
	C0_INSTR(store_f16,  f16,  2), \
	C0_INSTR(store_f32,  f32,  2), \
	C0_INSTR(store_f64,  f64,  2), \
	C0_INSTR(store_ptr,  ptr,  2), \
\
	C0_INSTR(clz_i8,   i8,      1), \
	C0_INSTR(clz_u8,   u8,      1), \
	C0_INSTR(clz_i16,  i16,     1), \
	C0_INSTR(clz_u16,  u16,     1), \
	C0_INSTR(clz_i32,  i32,     1), \
	C0_INSTR(clz_u32,  u32,     1), \
	C0_INSTR(clz_i64,  i64,     1), \
	C0_INSTR(clz_u64,  u64,     1), \
	C0_INSTR(clz_i128, i128,    1), \
	C0_INSTR(clz_u128, u128,    1), \
	C0_INSTR(ctz_i8,   i8,      1), \
	C0_INSTR(ctz_u8,   u8,      1), \
	C0_INSTR(ctz_i16,  i16,     1), \
	C0_INSTR(ctz_u16,  u16,     1), \
	C0_INSTR(ctz_i32,  i32,     1), \
	C0_INSTR(ctz_u32,  u32,     1), \
	C0_INSTR(ctz_i64,  i64,     1), \
	C0_INSTR(ctz_u64,  u64,     1), \
	C0_INSTR(ctz_i128, i128,    1), \
	C0_INSTR(ctz_u128, u128,    1), \
	C0_INSTR(popcnt_i8,   i8,   1), \
	C0_INSTR(popcnt_u8,   u8,   1), \
	C0_INSTR(popcnt_i16,  i16,  1), \
	C0_INSTR(popcnt_u16,  u16,  1), \
	C0_INSTR(popcnt_i32,  i32,  1), \
	C0_INSTR(popcnt_u32,  u32,  1), \
	C0_INSTR(popcnt_i64,  i64,  1), \
	C0_INSTR(popcnt_u64,  u64,  1), \
	C0_INSTR(popcnt_i128, i128, 1), \
	C0_INSTR(popcnt_u128, u128, 1), \
	C0_INSTR(abs_i8,   i8,      1), \
	C0_INSTR(abs_u8,   u8,      1), \
	C0_INSTR(abs_i16,  i16,     1), \
	C0_INSTR(abs_u16,  u16,     1), \
	C0_INSTR(abs_i32,  i32,     1), \
	C0_INSTR(abs_u32,  u32,     1), \
	C0_INSTR(abs_i64,  i64,     1), \
	C0_INSTR(abs_u64,  u64,     1), \
	C0_INSTR(abs_i128, i128,    1), \
	C0_INSTR(abs_u128, u128,    1), \
\
	C0_INSTR(negf_f16,     f16, 1), \
	C0_INSTR(negf_f32,     f32, 1), \
	C0_INSTR(negf_f64,     f64, 1), \
	C0_INSTR(absf_f16,     f16, 1), \
	C0_INSTR(absf_f32,     f32, 1), \
	C0_INSTR(absf_f64,     f64, 1), \
	C0_INSTR(ceilf_f16,    f16, 1), \
	C0_INSTR(ceilf_f32,    f32, 1), \
	C0_INSTR(ceilf_f64,    f64, 1), \
	C0_INSTR(floorf_f16,   f16, 1), \
	C0_INSTR(floorf_f32,   f32, 1), \
	C0_INSTR(floorf_f64,   f64, 1), \
	C0_INSTR(nearestf_f16, f16, 1), \
	C0_INSTR(nearestf_f32, f32, 1), \
	C0_INSTR(nearestf_f64, f64, 1), \
	C0_INSTR(truncf_f16,   f16, 1), \
	C0_INSTR(truncf_f32,   f32, 1), \
	C0_INSTR(truncf_f64,   f64, 1), \
	C0_INSTR(sqrtf_f16,    f16, 1), \
	C0_INSTR(sqrtf_f32,    f32, 1), \
	C0_INSTR(sqrtf_f64,    f64, 1), \
\
	C0_INSTR(add_i8,   i8,   2), \
	C0_INSTR(add_u8,   u8,   2), \
	C0_INSTR(add_i16,  i16,  2), \
	C0_INSTR(add_u16,  u16,  2), \
	C0_INSTR(add_i32,  i32,  2), \
	C0_INSTR(add_u32,  u32,  2), \
	C0_INSTR(add_i64,  i64,  2), \
	C0_INSTR(add_u64,  u64,  2), \
	C0_INSTR(add_i128, i128, 2), \
	C0_INSTR(add_u128, u128, 2), \
	C0_INSTR(sub_i8,   i8,   2), \
	C0_INSTR(sub_u8,   u8,   2), \
	C0_INSTR(sub_i16,  i16,  2), \
	C0_INSTR(sub_u16,  u16,  2), \
	C0_INSTR(sub_i32,  i32,  2), \
	C0_INSTR(sub_u32,  u32,  2), \
	C0_INSTR(sub_i64,  i64,  2), \
	C0_INSTR(sub_u64,  u64,  2), \
	C0_INSTR(sub_i128, i128, 2), \
	C0_INSTR(sub_u128, u128, 2), \
	C0_INSTR(mul_i8,   i8,   2), \
	C0_INSTR(mul_u8,   u8,   2), \
	C0_INSTR(mul_i16,  i16,  2), \
	C0_INSTR(mul_u16,  u16,  2), \
	C0_INSTR(mul_i32,  i32,  2), \
	C0_INSTR(mul_u32,  u32,  2), \
	C0_INSTR(mul_i64,  i64,  2), \
	C0_INSTR(mul_u64,  u64,  2), \
	C0_INSTR(mul_i128, i128, 2), \
	C0_INSTR(mul_u128, u128, 2), \
	C0_INSTR(quo_i8,   i8,   2), \
	C0_INSTR(quo_u8,   u8,   2), \
	C0_INSTR(quo_i16,  i16,  2), \
	C0_INSTR(quo_u16,  u16,  2), \
	C0_INSTR(quo_i32,  i32,  2), \
	C0_INSTR(quo_u32,  u32,  2), \
	C0_INSTR(quo_i64,  i64,  2), \
	C0_INSTR(quo_u64,  u64,  2), \
	C0_INSTR(quo_i128, i128, 2), \
	C0_INSTR(quo_u128, u128, 2), \
	C0_INSTR(rem_i8,   i8,   2), \
	C0_INSTR(rem_u8,   u8,   2), \
	C0_INSTR(rem_i16,  i16,  2), \
	C0_INSTR(rem_u16,  u16,  2), \
	C0_INSTR(rem_i32,  i32,  2), \
	C0_INSTR(rem_u32,  u32,  2), \
	C0_INSTR(rem_i64,  i64,  2), \
	C0_INSTR(rem_u64,  u64,  2), \
	C0_INSTR(rem_i128, i128, 2), \
	C0_INSTR(rem_u128, u128, 2), \
	C0_INSTR(shl_i8,   i8,   2), \
	C0_INSTR(shl_u8,   u8,   2), \
	C0_INSTR(shl_i16,  i16,  2), \
	C0_INSTR(shl_u16,  u16,  2), \
	C0_INSTR(shl_i32,  i32,  2), \
	C0_INSTR(shl_u32,  u32,  2), \
	C0_INSTR(shl_i64,  i64,  2), \
	C0_INSTR(shl_u64,  u64,  2), \
	C0_INSTR(shl_i128, i128, 2), \
	C0_INSTR(shl_u128, u128, 2), \
	C0_INSTR(shr_i8,   i8,   2), \
	C0_INSTR(shr_u8,   u8,   2), \
	C0_INSTR(shr_i16,  i16,  2), \
	C0_INSTR(shr_u16,  u16,  2), \
	C0_INSTR(shr_i32,  i32,  2), \
	C0_INSTR(shr_u32,  u32,  2), \
	C0_INSTR(shr_i64,  i64,  2), \
	C0_INSTR(shr_u64,  u64,  2), \
	C0_INSTR(shr_i128, i128, 2), \
	C0_INSTR(shr_u128, u128, 2), \
\
	C0_INSTR(and_i8,   i8,   2), \
	C0_INSTR(and_u8,   u8,   2), \
	C0_INSTR(and_i16,  i16,  2), \
	C0_INSTR(and_u16,  u16,  2), \
	C0_INSTR(and_i32,  i32,  2), \
	C0_INSTR(and_u32,  u32,  2), \
	C0_INSTR(and_i64,  i64,  2), \
	C0_INSTR(and_u64,  u64,  2), \
	C0_INSTR(and_i128, i128, 2), \
	C0_INSTR(and_u128, u128, 2), \
	C0_INSTR(or_i8,   i8,   2), \
	C0_INSTR(or_u8,   u8,   2), \
	C0_INSTR(or_i16,  i16,  2), \
	C0_INSTR(or_u16,  u16,  2), \
	C0_INSTR(or_i32,  i32,  2), \
	C0_INSTR(or_u32,  u32,  2), \
	C0_INSTR(or_i64,  i64,  2), \
	C0_INSTR(or_u64,  u64,  2), \
	C0_INSTR(or_i128, i128, 2), \
	C0_INSTR(or_u128, u128, 2), \
	C0_INSTR(xor_i8,   i8,   2), \
	C0_INSTR(xor_u8,   u8,   2), \
	C0_INSTR(xor_i16,  i16,  2), \
	C0_INSTR(xor_u16,  u16,  2), \
	C0_INSTR(xor_i32,  i32,  2), \
	C0_INSTR(xor_u32,  u32,  2), \
	C0_INSTR(xor_i64,  i64,  2), \
	C0_INSTR(xor_u64,  u64,  2), \
	C0_INSTR(xor_i128, i128, 2), \
	C0_INSTR(xor_u128, u128, 2), \
	C0_INSTR(eq_i8,   u8, 2), \
	C0_INSTR(eq_u8,   u8, 2), \
	C0_INSTR(eq_i16,  u8, 2), \
	C0_INSTR(eq_u16,  u8, 2), \
	C0_INSTR(eq_i32,  u8, 2), \
	C0_INSTR(eq_u32,  u8, 2), \
	C0_INSTR(eq_i64,  u8, 2), \
	C0_INSTR(eq_u64,  u8, 2), \
	C0_INSTR(eq_i128, u8, 2), \
	C0_INSTR(eq_u128, u8, 2), \
	C0_INSTR(neq_i8,   u8, 2), \
	C0_INSTR(neq_u8,   u8, 2), \
	C0_INSTR(neq_i16,  u8, 2), \
	C0_INSTR(neq_u16,  u8, 2), \
	C0_INSTR(neq_i32,  u8, 2), \
	C0_INSTR(neq_u32,  u8, 2), \
	C0_INSTR(neq_i64,  u8, 2), \
	C0_INSTR(neq_u64,  u8, 2), \
	C0_INSTR(neq_i128, u8, 2), \
	C0_INSTR(neq_u128, u8, 2), \
	C0_INSTR(lt_i8,   u8, 2), \
	C0_INSTR(lt_u8,   u8, 2), \
	C0_INSTR(lt_i16,  u8, 2), \
	C0_INSTR(lt_u16,  u8, 2), \
	C0_INSTR(lt_i32,  u8, 2), \
	C0_INSTR(lt_u32,  u8, 2), \
	C0_INSTR(lt_i64,  u8, 2), \
	C0_INSTR(lt_u64,  u8, 2), \
	C0_INSTR(lt_i128, u8, 2), \
	C0_INSTR(lt_u128, u8, 2), \
	C0_INSTR(gt_i8,   u8, 2), \
	C0_INSTR(gt_u8,   u8, 2), \
	C0_INSTR(gt_i16,  u8, 2), \
	C0_INSTR(gt_u16,  u8, 2), \
	C0_INSTR(gt_i32,  u8, 2), \
	C0_INSTR(gt_u32,  u8, 2), \
	C0_INSTR(gt_i64,  u8, 2), \
	C0_INSTR(gt_u64,  u8, 2), \
	C0_INSTR(gt_i128, u8, 2), \
	C0_INSTR(gt_u128, u8, 2), \
	C0_INSTR(lteq_i8,   u8, 2), \
	C0_INSTR(lteq_u8,   u8, 2), \
	C0_INSTR(lteq_i16,  u8, 2), \
	C0_INSTR(lteq_u16,  u8, 2), \
	C0_INSTR(lteq_i32,  u8, 2), \
	C0_INSTR(lteq_u32,  u8, 2), \
	C0_INSTR(lteq_i64,  u8, 2), \
	C0_INSTR(lteq_u64,  u8, 2), \
	C0_INSTR(lteq_i128, u8, 2), \
	C0_INSTR(lteq_u128, u8, 2), \
	C0_INSTR(gteq_i8,   u8, 2), \
	C0_INSTR(gteq_u8,   u8, 2), \
	C0_INSTR(gteq_i16,  u8, 2), \
	C0_INSTR(gteq_u16,  u8, 2), \
	C0_INSTR(gteq_i32,  u8, 2), \
	C0_INSTR(gteq_u32,  u8, 2), \
	C0_INSTR(gteq_i64,  u8, 2), \
	C0_INSTR(gteq_u64,  u8, 2), \
	C0_INSTR(gteq_i128, u8, 2), \
	C0_INSTR(gteq_u128, u8, 2), \
	C0_INSTR(min_i8,   i8,   2), \
	C0_INSTR(min_u8,   u8,   2), \
	C0_INSTR(min_i16,  i16,  2), \
	C0_INSTR(min_u16,  u16,  2), \
	C0_INSTR(min_i32,  i32,  2), \
	C0_INSTR(min_u32,  u32,  2), \
	C0_INSTR(min_i64,  i64,  2), \
	C0_INSTR(min_u64,  u64,  2), \
	C0_INSTR(min_i128, i128, 2), \
	C0_INSTR(min_u128, u128, 2), \
	C0_INSTR(max_i8,   i8,   2), \
	C0_INSTR(max_u8,   u8,   2), \
	C0_INSTR(max_i16,  i16,  2), \
	C0_INSTR(max_u16,  u16,  2), \
	C0_INSTR(max_i32,  i32,  2), \
	C0_INSTR(max_u32,  u32,  2), \
	C0_INSTR(max_i64,  i64,  2), \
	C0_INSTR(max_u64,  u64,  2), \
	C0_INSTR(max_i128, i128, 2), \
	C0_INSTR(max_u128, u128, 2), \
\
	C0_INSTR(addf_f16,  f16, 2), \
	C0_INSTR(addf_f32,  f32, 2), \
	C0_INSTR(addf_f64,  f64, 2), \
	C0_INSTR(subf_f16,  f16, 2), \
	C0_INSTR(subf_f32,  f32, 2), \
	C0_INSTR(subf_f64,  f64, 2), \
	C0_INSTR(mulf_f16,  f16, 2), \
	C0_INSTR(mulf_f32,  f32, 2), \
	C0_INSTR(mulf_f64,  f64, 2), \
	C0_INSTR(divf_f16,  f16, 2), \
	C0_INSTR(divf_f32,  f32, 2), \
	C0_INSTR(divf_f64,  f64, 2), \
	C0_INSTR(eqf_f16,    u8, 2), \
	C0_INSTR(eqf_f32,    u8, 2), \
	C0_INSTR(eqf_f64,    u8, 2), \
	C0_INSTR(neqf_f16,   u8, 2), \
	C0_INSTR(neqf_f32,   u8, 2), \
	C0_INSTR(neqf_f64,   u8, 2), \
	C0_INSTR(ltf_f16,    u8, 2), \
	C0_INSTR(ltf_f32,    u8, 2), \
	C0_INSTR(ltf_f64,    u8, 2), \
	C0_INSTR(gtf_f16,    u8, 2), \
	C0_INSTR(gtf_f32,    u8, 2), \
	C0_INSTR(gtf_f64,    u8, 2), \
	C0_INSTR(lteqf_f16,  u8, 2), \
	C0_INSTR(lteqf_f32,  u8, 2), \
	C0_INSTR(lteqf_f64,  u8, 2), \
	C0_INSTR(gteqf_f16,  u8, 2), \
	C0_INSTR(gteqf_f32,  u8, 2), \
	C0_INSTR(gteqf_f64,  u8, 2), \
\
	C0_INSTR(convert,     void, 1), \
	C0_INSTR(reinterpret, void, 1), \
\
	C0_INSTR(atomic_thread_fence, void, 0), \
	C0_INSTR(atomic_signal_fence, void, 0), \
\
	C0_INSTR(atomic_load_i8,    i8,   1), \
	C0_INSTR(atomic_load_u8,    u8,   1), \
	C0_INSTR(atomic_load_i16,   i16,  1), \
	C0_INSTR(atomic_load_u16,   u16,  1), \
	C0_INSTR(atomic_load_i32,   i32,  1), \
	C0_INSTR(atomic_load_u32,   u32,  1), \
	C0_INSTR(atomic_load_i64,   i64,  1), \
	C0_INSTR(atomic_load_u64,   u64,  1), \
	C0_INSTR(atomic_load_i128,  i128, 1), \
	C0_INSTR(atomic_load_u128,  u128, 1), \
	C0_INSTR(atomic_load_f16,   f16,  1), \
	C0_INSTR(atomic_load_f32,   f32,  1), \
	C0_INSTR(atomic_load_f64,   f64,  1), \
	C0_INSTR(atomic_load_ptr,   ptr,  1), \
	C0_INSTR(atomic_store_i8,   i8,   2), \
	C0_INSTR(atomic_store_u8,   u8,   2), \
	C0_INSTR(atomic_store_i16,  i16,  2), \
	C0_INSTR(atomic_store_u16,  u16,  2), \
	C0_INSTR(atomic_store_i32,  i32,  2), \
	C0_INSTR(atomic_store_u32,  u32,  2), \
	C0_INSTR(atomic_store_i64,  i64,  2), \
	C0_INSTR(atomic_store_u64,  u64,  2), \
	C0_INSTR(atomic_store_i128, i128, 2), \
	C0_INSTR(atomic_store_u128, u128, 2), \
	C0_INSTR(atomic_store_f16,  f16,  2), \
	C0_INSTR(atomic_store_f32,  f32,  2), \
	C0_INSTR(atomic_store_f64,  f64,  2), \
	C0_INSTR(atomic_store_ptr,  ptr,  2), \
\
	C0_INSTR(atomic_xchg_i8,   u8, 2), \
	C0_INSTR(atomic_xchg_u8,   u8, 2), \
	C0_INSTR(atomic_xchg_i16,  u8, 2), \
	C0_INSTR(atomic_xchg_u16,  u8, 2), \
	C0_INSTR(atomic_xchg_i32,  u8, 2), \
	C0_INSTR(atomic_xchg_u32,  u8, 2), \
	C0_INSTR(atomic_xchg_i64,  u8, 2), \
	C0_INSTR(atomic_xchg_u64,  u8, 2), \
	C0_INSTR(atomic_xchg_i128, u8, 2), \
	C0_INSTR(atomic_xchg_u128, u8, 2), \
	C0_INSTR(atomic_xchg_f16,  u8, 2), \
	C0_INSTR(atomic_xchg_f32,  u8, 2), \
	C0_INSTR(atomic_xchg_f64,  u8, 2), \
	C0_INSTR(atomic_cas_i8,    void, 3), \
	C0_INSTR(atomic_cas_u8,    void, 3), \
	C0_INSTR(atomic_cas_i16,   void, 3), \
	C0_INSTR(atomic_cas_u16,   void, 3), \
	C0_INSTR(atomic_cas_i32,   void, 3), \
	C0_INSTR(atomic_cas_u32,   void, 3), \
	C0_INSTR(atomic_cas_i64,   void, 3), \
	C0_INSTR(atomic_cas_u64,   void, 3), \
	C0_INSTR(atomic_cas_i128,  void, 3), \
	C0_INSTR(atomic_cas_u128,  void, 3), \
	C0_INSTR(atomic_cas_f16,   void, 3), \
	C0_INSTR(atomic_cas_f32,   void, 3), \
	C0_INSTR(atomic_cas_f64,   void, 3), \
\
	C0_INSTR(atomic_add_i8,   i8,   2), \
	C0_INSTR(atomic_add_u8,   u8,   2), \
	C0_INSTR(atomic_add_i16,  i16,  2), \
	C0_INSTR(atomic_add_u16,  u16,  2), \
	C0_INSTR(atomic_add_i32,  i32,  2), \
	C0_INSTR(atomic_add_u32,  u32,  2), \
	C0_INSTR(atomic_add_i64,  i64,  2), \
	C0_INSTR(atomic_add_u64,  u64,  2), \
	C0_INSTR(atomic_add_i128, i128, 2), \
	C0_INSTR(atomic_add_u128, u128, 2), \
	C0_INSTR(atomic_addf_f16,  f16, 2), \
	C0_INSTR(atomic_addf_f32,  f32, 2), \
	C0_INSTR(atomic_addf_f64,  f64, 2), \
	C0_INSTR(atomic_sub_i8,   i8,   2), \
	C0_INSTR(atomic_sub_u8,   u8,   2), \
	C0_INSTR(atomic_sub_i16,  i16,  2), \
	C0_INSTR(atomic_sub_u16,  u16,  2), \
	C0_INSTR(atomic_sub_i32,  i32,  2), \
	C0_INSTR(atomic_sub_u32,  u32,  2), \
	C0_INSTR(atomic_sub_i64,  i64,  2), \
	C0_INSTR(atomic_sub_u64,  u64,  2), \
	C0_INSTR(atomic_sub_i128, i128, 2), \
	C0_INSTR(atomic_sub_u128, u128, 2), \
	C0_INSTR(atomic_subf_f16,  f16, 2), \
	C0_INSTR(atomic_subf_f32,  f32, 2), \
	C0_INSTR(atomic_subf_f64,  f64, 2), \
	C0_INSTR(atomic_and_i8,   i8,   2), \
	C0_INSTR(atomic_and_u8,   u8,   2), \
	C0_INSTR(atomic_and_i16,  i16,  2), \
	C0_INSTR(atomic_and_u16,  u16,  2), \
	C0_INSTR(atomic_and_i32,  i32,  2), \
	C0_INSTR(atomic_and_u32,  u32,  2), \
	C0_INSTR(atomic_and_i64,  i64,  2), \
	C0_INSTR(atomic_and_u64,  u64,  2), \
	C0_INSTR(atomic_and_i128, i128, 2), \
	C0_INSTR(atomic_and_u128, u128, 2), \
	C0_INSTR(atomic_or_i8,   i8,   2), \
	C0_INSTR(atomic_or_u8,   u8,   2), \
	C0_INSTR(atomic_or_i16,  i16,  2), \
	C0_INSTR(atomic_or_u16,  u16,  2), \
	C0_INSTR(atomic_or_i32,  i32,  2), \
	C0_INSTR(atomic_or_u32,  u32,  2), \
	C0_INSTR(atomic_or_i64,  i64,  2), \
	C0_INSTR(atomic_or_u64,  u64,  2), \
	C0_INSTR(atomic_or_i128, i128, 2), \
	C0_INSTR(atomic_or_u128, u128, 2), \
	C0_INSTR(atomic_xor_i8,   i8,   2), \
	C0_INSTR(atomic_xor_u8,   u8,   2), \
	C0_INSTR(atomic_xor_i16,  i16,  2), \
	C0_INSTR(atomic_xor_u16,  u16,  2), \
	C0_INSTR(atomic_xor_i32,  i32,  2), \
	C0_INSTR(atomic_xor_u32,  u32,  2), \
	C0_INSTR(atomic_xor_i64,  i64,  2), \
	C0_INSTR(atomic_xor_u64,  u64,  2), \
	C0_INSTR(atomic_xor_i128, i128, 2), \
	C0_INSTR(atomic_xor_u128, u128, 2), \
\
	C0_INSTR(memmove, void, 3), \
	C0_INSTR(memset,  void, 3), \
\
	C0_INSTR(decl, void, 0), \
	C0_INSTR(addr, ptr, 1), \
\
	C0_INSTR(call,  void, -1), \
\
	C0_INSTR(select_i8,   i8,   3), \
	C0_INSTR(select_u8,   u8,   3), \
	C0_INSTR(select_i16,  i16,  3), \
	C0_INSTR(select_u16,  u16,  3), \
	C0_INSTR(select_i32,  i32,  3), \
	C0_INSTR(select_u32,  u32,  3), \
	C0_INSTR(select_i64,  i64,  3), \
	C0_INSTR(select_u64,  u64,  3), \
	C0_INSTR(select_i128, i128, 3), \
	C0_INSTR(select_u128, u128, 3), \
	C0_INSTR(select_f16,  f16,  3), \
	C0_INSTR(select_f32,  f32,  3), \
	C0_INSTR(select_f64,  f64,  3), \
	C0_INSTR(select_ptr,  ptr,  3), \
\
	C0_INSTR(if,    void, -1), \
	C0_INSTR(loop,  void, 0), \
	C0_INSTR(block, void, 0), \
\
	C0_INSTR(continue,    void, 0), \
	C0_INSTR(break,       void, 0), \
	C0_INSTR(return,      void, -1), \
	C0_INSTR(unreachable, void, 0), \
	C0_INSTR(goto,        void, 1), \
	C0_INSTR(label,       void, 0), \



typedef u16 C0InstrKind;
enum C0InstrKind_enum {
#define C0_INSTR(name, type, arg_count) C0Instr_##name
	C0_INSTR_TABLE
#undef C0_INSTR
	C0Instr_COUNT
};

static char const *const c0_instr_names[C0Instr_COUNT] = {
#define C0_INSTR(name, type, arg_count) #name
	C0_INSTR_TABLE
#undef C0_INSTR
};

static C0BasicType const c0_instr_ret_type[C0Instr_COUNT] = {
#define C0_INSTR(name, type, arg_count) C0Basic_##type
	C0_INSTR_TABLE
#undef C0_INSTR
};

// negative value implies a variable length
static i32 const c0_instr_arg_count[C0Instr_COUNT] = {
#define C0_INSTR(name, type, arg_count) arg_count
	C0_INSTR_TABLE
#undef C0_INSTR
};


struct C0Gen {
	C0String name;
	C0Arena  arena;

	i64 ptr_size;

	C0Array(C0String)    files;
	C0Array(C0AggType *) types;
	C0Array(C0Proc *)    procs;
};

struct C0Loc {
	u32 file;
	i32 line;
	i32 column;
};

struct C0Instr {
	C0InstrKind kind;
	C0BasicType basic_type;
	u16         padding0;
	u32         uses;
	C0Instr *   parent;

	C0AggType *agg_type;

	u32      id;
	C0String name;
	C0Proc  *call_proc;

	C0Instr **args;
	usize     args_len;

	C0Array(C0Instr *) nested_instrs;

	union {
		i64 value_i64;
		u64 value_u64;

		u16 value_f16;
		f32 value_f32;
		f64 value_f64;
	};
};

struct C0Proc {
	C0Arena *  arena;
	C0Gen *    gen;
	C0String   name;
	C0AggType *sig;

	C0Array(C0Instr *) instrs;
	C0Array(C0Instr *) nested_blocks;
	C0Array(C0Instr *) labels;
};

typedef u32 C0AggTypeKind;
enum C0AggTypeKind_enum {
	C0AggType_basic,
	C0AggType_array,
	C0AggType_record,
	C0AggType_proc,

	C0AggType_COUNT
};

typedef u16 C0ProcCallConv;
enum C0ProcCallConv_enum {
	C0ProcCallConv_cdecl,
	C0ProcCallConv_stdcall,
	C0ProcCallConv_fastcall,
};
typedef u16 C0ProcFlags;
enum C0ProcFlags_enum {
	C0ProcFlag_diverging     = 1<<0,
	C0ProcFlag_variadic      = 1<<1,
	C0ProcFlag_always_inline = 1<<2, // should not be needed in the future
	C0ProcFlag_never_inline  = 1<<3,
};

struct C0AggType {
	C0AggTypeKind kind;
	u32        padding0;
	i64        size;
	i64        align;

	union {
		struct {
			C0BasicType type;
		} basic;
		struct {
			C0AggType *elem;
			i64        len;
		} array;
		struct {
			C0String name;
			C0Array(C0String)    names;
			C0Array(C0AggType *) types;
			C0Array(i64)         aligns;
		} record;
		struct {
			C0AggType *          ret;
			C0Array(C0String)    names;
			C0Array(C0AggType *) types;

			C0ProcCallConv call_conv;
			C0ProcFlags    flags;
		} proc;
	};
};

void c0_platform_virtual_memory_init(void);

void c0_gen_init(C0Gen *gen);
void c0_gen_destroy(C0Gen *gen);

C0Proc * c0_proc_create (C0Gen *gen, C0String name);
C0Instr *c0_instr_create(C0Proc *p,  C0InstrKind kind);
C0Instr *c0_instr_push  (C0Proc *p,  C0Instr *instr);


C0Instr *c0_push_nested_block(C0Proc *p, C0Instr *block);
C0Instr *c0_push_basic_i8(C0Proc *p, i8 value);
C0Instr *c0_push_basic_u8(C0Proc *p, u8 value);
C0Instr *c0_push_basic_i16(C0Proc *p, i16 value);
C0Instr *c0_push_basic_u16(C0Proc *p, u16 value);
C0Instr *c0_push_basic_i32(C0Proc *p, i32 value);
C0Instr *c0_push_basic_u32(C0Proc *p, u32 value);
C0Instr *c0_push_basic_i64(C0Proc *p, i64 value);
C0Instr *c0_push_basic_u64(C0Proc *p, u64 value);
C0Instr *c0_push_basic_ptr(C0Proc *p, u64 value);
C0Instr *c0_push_bin(C0Proc *p, C0InstrKind kind, C0Instr *left, C0Instr *right);

C0Instr *c0_push_negf(C0Proc *p, C0Instr *arg);
C0Instr *c0_push_noti(C0Proc *p, C0Instr *arg);
C0Instr *c0_push_notb(C0Proc *p, C0Instr *arg);
C0Instr *c0_push_unreachable(C0Proc *p);
C0Instr *c0_push_return(C0Proc *p, C0Instr *arg);
C0Instr *c0_push_convert(C0Proc *p, C0BasicType type, C0Instr *arg);
C0Instr *c0_push_load_basic(C0Proc *p, C0BasicType type, C0Instr *arg);
C0Instr *c0_push_addr_of_decl(C0Proc *p, C0Instr *decl);
C0Instr *c0_push_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src);
C0Instr *c0_push_copy_basic(C0Proc *p, C0Instr *arg);
C0Instr *c0_push_unaligned_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src);
C0Instr *c0_push_atomic_thread_fence(C0Proc *p);
C0Instr *c0_push_atomic_signal_fence(C0Proc *p);
C0Instr *c0_push_atomic_load_basic(C0Proc *p, C0BasicType type, C0Instr *arg);
C0Instr *c0_push_atomic_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src);
C0Instr *c0_push_atomic_cas(C0Proc *p, C0Instr *obj, C0Instr *expected, C0Instr *desired);
C0Instr *c0_push_atomic_bin(C0Proc *p, C0InstrKind kind, C0Instr *dst, C0Instr *src);

C0Instr *c0_push_memmove(C0Proc *p, C0Instr *dst, C0Instr *src, C0Instr *size);
C0Instr *c0_push_memset(C0Proc *p, C0Instr *dst, u8 val, C0Instr *size);
C0Instr *c0_push_decl_basic(C0Proc *p, C0BasicType type, C0String name);
C0Instr *c0_push_select_basic(C0Proc *p, C0Instr *cond, C0Instr *true_case, C0Instr *false_case);
C0Instr *c0_push_continue(C0Proc *p);
C0Instr *c0_push_break(C0Proc *p);
C0Instr *c0_push_goto(C0Proc *p, C0Instr *label);
C0Instr *c0_push_label(C0Proc *p, C0String name);
C0Instr *c0_push_if(C0Proc *p, C0Instr *cond);
C0Instr *c0_push_loop(C0Proc *p);

#endif /*C0_HEADER_DEFINE*/