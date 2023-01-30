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


#if !defined(C0_THREAD_LOCAL)
	#if defined(_MSC_VER) && _MSC_VER >= 1300
		#define C0_THREAD_LOCAL __declspec(thread)
	#elif defined(__GNUC__)
		#define C0_THREAD_LOCAL __thread
	#elif defined(__TSDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
		#define C0_THREAD_LOCAL _Thread_local
	#else
		#define C0_THREAD_LOCAL thread_local
	#endif
#endif

typedef struct C0String      C0String;
typedef struct C0Allocator      C0Allocator;
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

#ifndef C0_DEBUG_TRAP
	#if defined(_MSC_VER)
	 	#if _MSC_VER < 1300
		#define C0_DEBUG_TRAP() __asm int 3 /* Trap to debugger! */
		#else
		#define C0_DEBUG_TRAP() __debugbreak()
		#endif
	#else
		#define C0_DEBUG_TRAP() __builtin_trap()
	#endif
#endif

static void c0_assert_handler(char const *prefix, char const *condition, char const *file, int line, char const *msg, ...);

#ifndef C0_ASSERT_MSG
#define C0_ASSERT_MSG(cond, msg, ...) do { \
	if (!(cond)) { \
		c0_assert_handler("Assertion Failure", #cond, __FILE__, __LINE__, msg, ##__VA_ARGS__); \
		C0_DEBUG_TRAP(); \
	} \
} while (0)
#endif

#ifndef C0_ASSERT
#define C0_ASSERT(cond) C0_ASSERT_MSG(cond, NULL)
#endif
#ifndef C0_PANIC
#define C0_PANIC(msg) C0_ASSERT_MSG(0, msg)
#endif


// printf("%.*s", C0PSTR(s));
#ifndef C0PSTR
#define C0PSTR(s) (int)(s).len, (s).text
#endif

struct C0Array {
	alignas(2*sizeof(isize))
	isize len;
	isize cap;
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
	C0_ASSERT((usize)index < (usize)c0array_len(array)); \
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
	C0_BASIC(void, "void",     0,  false), \
	C0_BASIC(i8,   "i8",       1,  true),  \
	C0_BASIC(u8,   "u8",       1,  false), \
	C0_BASIC(i16,  "i16",      2,  true),  \
	C0_BASIC(u16,  "u16",      2,  false), \
	C0_BASIC(i32,  "i32",      4,  true),  \
	C0_BASIC(u32,  "u32",      4,  false), \
	C0_BASIC(i64,  "i64",      8,  true),  \
	C0_BASIC(u64,  "u64",      8,  false), \
	C0_BASIC(i128, "i128",     16, true),  \
	C0_BASIC(u128, "u128",     16, false), \
	C0_BASIC(f16,  "f16",      2,  true),  \
	C0_BASIC(f32,  "f32",      4,  true),  \
	C0_BASIC(f64,  "f64",      8,  true),  \
	C0_BASIC(ptr,  "void *",  -1, false), /*-1 denotes that the size is `-(-1) * pointer_size`*/ \

typedef u8 C0BasicType;
enum C0BasicType_enum {
#define C0_BASIC(name, str, size, is_signed) C0Basic_##name
	C0_BASIC_TABLE
#undef C0_BASIC
	C0Basic_COUNT
};

static i32 const c0_basic_type_sizes[C0Basic_COUNT] = {
#define C0_BASIC(name, str, size, is_signed) size
	C0_BASIC_TABLE
#undef C0_BASIC
};

static char const *const c0_basic_names[C0Basic_COUNT] = {
#define C0_BASIC(name, str, size, is_signed) str
	C0_BASIC_TABLE
#undef C0_BASIC
};
static bool const c0_basic_is_signed[C0Basic_COUNT] = {
#define C0_BASIC(name, str, size, is_signed) is_signed
	C0_BASIC_TABLE
#undef C0_BASIC
};

static C0BasicType c0_basic_unsigned_type[C0Basic_COUNT] = {
	C0Basic_void,
	C0Basic_u8,
	C0Basic_u8,
	C0Basic_u16,
	C0Basic_u16,
	C0Basic_u32,
	C0Basic_u32,
	C0Basic_u64,
	C0Basic_u64,
	C0Basic_u128,
	C0Basic_u128,
	C0Basic_f16,
	C0Basic_f32,
	C0Basic_f64,
	C0Basic_ptr,
};

static u8 c0_basic_unsigned_instr_offset[C0Basic_COUNT] = {
	0,
	0,
	0,
	1,
	1,
	2,
	2,
	3,
	3,
	4,
	4,
	5,
	6,
	7,
	8,
};




typedef u16 C0InstrKind;
enum C0InstrKind_enum {
#define C0_INSTR(name, arg_type, ret_type, arg_count, symbol) C0Instr_##name,
	#include "c0_instr.h"
#undef C0_INSTR
	C0Instr_COUNT
};

static char const *const c0_instr_names[C0Instr_COUNT] = {
#define C0_INSTR(name, arg_type, ret_type, arg_count, symbol) #name,
	#include "c0_instr.h"
#undef C0_INSTR
};

static C0BasicType const c0_instr_arg_type[C0Instr_COUNT] = {
#define C0_INSTR(name, arg_type, ret_type, arg_count, symbol) C0Basic_##arg_type,
	#include "c0_instr.h"
#undef C0_INSTR
};

static C0BasicType const c0_instr_ret_type[C0Instr_COUNT] = {
#define C0_INSTR(name, arg_type, ret_type, arg_count, symbol) C0Basic_##ret_type,
	#include "c0_instr.h"
#undef C0_INSTR
};

// negative value implies a variable length
static i32 const c0_instr_arg_count[C0Instr_COUNT] = {
#define C0_INSTR(name, arg_type, ret_type, arg_count, symbol) arg_count,
	#include "c0_instr.h"
#undef C0_INSTR
};

// negative value implies a variable length
static char const *const c0_instr_symbols[C0Instr_COUNT] = {
#define C0_INSTR(name, arg_type, ret_type, arg_count, symbol) symbol,
	#include "c0_instr.h"
#undef C0_INSTR
};

typedef u8 C0EndianKind;
enum C0EndianKind_enum {
	C0Endian_little = 0,
	C0Endian_big    = 1,
};

struct C0Gen {
	C0String name;
	C0Arena  arena;

	i64 ptr_size;
	C0EndianKind endian;

	C0Array(C0String)    files;
	C0Array(C0AggType *) types;
	C0Array(C0Proc *)    procs;

	C0AggType *basic_agg[C0Basic_COUNT];

	u8 instrs_to_generate[C0Instr_COUNT];
	u8 convert_to_generate[C0Basic_COUNT][C0Basic_COUNT];
	u8 reinterpret_to_generate[C0Basic_COUNT][C0Basic_COUNT];
};

struct C0Loc {
	u32 file;
	i32 line;
	i32 column;
};

typedef u32 C0InstrFlags;
enum C0InstrFlags_enum {
	C0InstrFlag_print_inline = 1u<<16u,
};

struct C0Instr {
	C0InstrKind  kind;
	C0BasicType  basic_type;
	u16          padding0;
	u32          uses;
	u32          alignment; // optional
	C0Instr *    parent;
	C0InstrFlags flags;

	C0AggType *agg_type; // if set, overrides `basic_type`

	u32      id;
	C0String name;
	C0Proc    *call_proc;
	C0AggType *call_sig;

	/*
		unary expression:  args_len == 1
		conversion:        args_len == 1
		binary expression: args_len == 2
		load:              args_len == 1
		store:             args_len == 2
		addr:              args_len == 1
		index_ptr:         args_len == 2
		atomic_cas:        args_len == 3
			args[0] : obj
			args[1] : expected
			args[2] : desired
		memmove: args_len == 3
			args[0] : dst
			args[1] : src
			args[2] : size
		memset: args_len == 3
			args[0] : dst
			args[1] : val
			args[2] : size
		if statement
			args[0] : condition
			args[1] : else statement
		return statement
			args[0] : return value (if exists)
	*/
	C0Instr **args;
	isize     args_len;

	/*
		block
		if (block) (not else statement)
		loop
	*/
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
	void *     user_data;

	C0Array(C0Instr *) parameters;
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
C0Instr *c0_push_bin(C0Proc *p, C0InstrKind kind, C0BasicType type, C0Instr *left, C0Instr *right);

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