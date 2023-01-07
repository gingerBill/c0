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


typedef struct C0Gen   C0Gen;
typedef struct C0Instr C0Instr;
typedef struct C0Proc  C0Proc;
typedef struct C0Type  C0Type;
typedef struct C0Loc   C0Loc;

typedef u8 C0BasicType;
enum C0BasicType_enum {
	C0Basic_void,
	C0Basic_i8,
	C0Basic_u8,
	C0Basic_i16,
	C0Basic_u16,
	C0Basic_i32,
	C0Basic_u32,
	C0Basic_i64,
	C0Basic_u64,
	C0Basic_i128,
	C0Basic_u128,
	C0Basic_f16,
	C0Basic_f32,
	C0Basic_f64,
	C0Basic_ptr,

	C0Basic_COUNT
};

static i32 const c0_basic_type_size[C0Basic_COUNT] = {
	0  /* void */,
	1  /* i8   */,
	1  /* u8   */,
	2  /* i16  */,
	2  /* u16  */,
	4  /* i32  */,
	4  /* u32  */,
	8  /* i64  */,
	8  /* u64  */,
	16 /* i128 */,
	16 /* u128 */,
	2  /* f16  */,
	4  /* f32  */,
	8  /* f64  */,
	-1 /* ptr  */, // -1 denotes that the size is `-(-1) * pointer_size`
};

static char const *const c0_basic_names[C0Basic_COUNT] = {
	"void",
	"i8",
	"u8",
	"i16",
	"u16",
	"i32",
	"u32",
	"i64",
	"u64",
	"i128",
	"u128",
	"f16",
	"f32",
	"f64",
	"void *",
};


typedef u8 C0InstrKind;
enum C0InstrKind_enum {
	C0Instr_invalid,

	// ptr
	C0Instr_load,
	C0Instr_store,

	// unary
	C0Instr_negf,

	// binary
	C0Instr_add,
	C0Instr_sub,
	C0Instr_mul,
	C0Instr_quoi,
	C0Instr_quou,
	C0Instr_remi,
	C0Instr_remu,
	C0Instr_shli,
	C0Instr_shlu,
	C0Instr_shri,
	C0Instr_shru,

	C0Instr_and,
	C0Instr_or,
	C0Instr_xor,
	C0Instr_eq,
	C0Instr_neq,
	C0Instr_lti,
	C0Instr_ltu,
	C0Instr_gti,
	C0Instr_gtu,
	C0Instr_lteqi,
	C0Instr_ltequ,
	C0Instr_gteqi,
	C0Instr_gtequ,

	C0Instr_addf,
	C0Instr_subf,
	C0Instr_mulf,
	C0Instr_divf,
	C0Instr_eqf,
	C0Instr_neqf,
	C0Instr_ltf,
	C0Instr_gtf,
	C0Instr_lteqf,
	C0Instr_gteqf,

	// conversion
	C0Instr_cvt,

	// atomic
	C0Instr_atomic_thread_fence,
	C0Instr_atomic_signal_fence,

	C0Instr_atomic_load,
	C0Instr_atomic_store,
	C0Instr_atomic_xchg,
	C0Instr_atomic_cas,
	C0Instr_atomic_add,
	C0Instr_atomic_sub,
	C0Instr_atomic_and,
	C0Instr_atomic_or,
	C0Instr_atomic_xor,

	// memory
	C0Instr_memmove,
	C0Instr_memset,

	// declarations
	C0Instr_decl,
	C0Instr_addr,

	// call
	C0Instr_call,

	// ternary
	C0Instr_select,

	// blocks
	C0Instr_if,
	C0Instr_loop,
	C0Instr_block,

	// branch
	C0Instr_continue,
	C0Instr_break,
	C0Instr_return,
	C0Instr_goto,
	C0Instr_label,

	C0Instr_COUNT
};

static char const *const c0_instr_names[C0Instr_COUNT] = {
	"invalid",

	"load",
	"store",

	"negf",

	"add",
	"sub",
	"mul",
	"quoi",
	"quou",
	"remi",
	"remu",
	"shli",
	"shlu",
	"shri",
	"shru",

	"and",
	"or",
	"xor",
	"eq",
	"neq",
	"lt",
	"gt",
	"lteq",
	"gteq",

	"addf",
	"subf",
	"mulf",
	"divf",
	"eqf",
	"neqf",
	"ltf",
	"gtf",
	"lteqf",
	"gteqf",

	"cvt",

	"atomic_thread_fence",
	"atomic_signal_fence",

	"atomic_load",
	"atomic_store",
	"atomic_xchg",
	"atomic_cas",
	"atomic_add",
	"atomic_sub",
	"atomic_and",
	"atomic_or",
	"atomic_xor",

	"memmove",
	"memset",

	"decl",
	"addr",

	"call",

	"select",

	"if",
	"loop",
	"block",

	"continue",
	"break",
	"return",
	"goto",
	"label",
};

struct C0Gen {
	C0String name;
	C0Arena  arena;

	C0Array(C0String) files;
	C0Array(C0Type *) types;
	C0Array(C0Proc *) procs;
};

struct C0Loc {
	u32 file;
	i32 line;
	i32 column;
};

struct C0Instr {
	C0InstrKind kind;
	C0BasicType basic_type;
	u32         uses;
	C0Type *    type;
	C0Instr *   parent;

	u32      id;
	C0String name;
	C0Proc  *proc;

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
	C0Arena *        arena;
	C0Gen *          gen;
	C0String         name;

	C0Array(C0Instr *) instrs;
	C0Array(C0Instr *) nested_blocks;
};

typedef u32 C0TypeKind;
enum C0TypeKind_enum {
	C0Type_invalid,

	C0Type_basic,
	C0Type_array,
	C0Type_record,

	C0Type_COUNT
};

struct C0Type {
	C0TypeKind kind;
	i64 size;
	i64 align;

	union {
		struct {
			C0Type *elem;
			i64     len;
		} array;
		struct {
			C0String *names;
			C0Type *  types;
			isize     fields_len;
		} record;
	};
};

void c0_platform_virtual_memory_init(void);

void c0_gen_init(C0Gen *gen);
void c0_gen_destroy(C0Gen *gen);

C0Proc * c0_proc_create (C0Gen *gen, C0String name);
C0Instr *c0_instr_create(C0Proc *p,  C0InstrKind kind);
C0Instr *c0_instr_push  (C0Proc *p,  C0Instr *instr);


#endif /*C0_HEADER_DEFINE*/