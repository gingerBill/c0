#include "c0.h"
#include <stdlib.h>
#include <assert.h>

#if !defined(GB_NO_WINDOWS_H)
	#define NOMINMAX            1
	#if !defined(GB_WINDOWS_H_INCLUDED)
	#define WIN32_LEAN_AND_MEAN 1
	#define WIN32_MEAN_AND_LEAN 1
	#define VC_EXTRALEAN        1
	#endif
	#include <windows.h>
	#undef NOMINMAX
	#if !defined(GB_WINDOWS_H_INCLUDED)
	#undef WIN32_LEAN_AND_MEAN
	#undef WIN32_MEAN_AND_LEAN
	#undef VC_EXTRALEAN
	#endif
#endif

#if defined(__cplusplus)
	#include <atomic>
	#define C0Atomic(T) std::atomic<T>
	#define c0_atomic_fetch_add(ptr, x) (ptr)->fetch_add((x))
	#define c0_atomic_fetch_sub(ptr, x) (ptr)->fetch_sub((x))
	#define c0_atomic_load(ptr)         (ptr)->load()
	#define c0_atomic_store(ptr, x)     (ptr)->store((x))
#else
	#define C0Atomic(T) _Atomic T
	#define c0_atomic_fetch_add(ptr, x) atomic_fetch_add((ptr), (x))
	#define c0_atomic_fetch_sub(ptr, x) atomic_fetch_sub((ptr), (x))
	#define c0_atomic_load(ptr)         atomic_load((ptr))
	#define c0_atomic_store(ptr, x)     atomic_store((ptr), (x))
#endif

bool c0array_grow_internal(void **const array, usize elements, usize type_size) {
	usize count = 0;
	void *data = 0;
	if (*array) {
		C0Array *const meta = c0array_meta(*array);
		count = 2 * meta->cap + elements;
		data = realloc(meta, type_size * count + sizeof(*meta));
		if (!data) {
			free(meta);
			return false;
		}
	} else {
		count = elements + 1;
		data = malloc(type_size * count + sizeof(C0Array));
		if (!data) {
			return false;
		}
		((C0Array *)data)->len = 0;
	}
	C0Array *meta = (C0Array *)data;
	meta->cap = count;
	*array = meta + 1;
	return true;
}
void c0array_delete(void *const array) {
	if (array) {
		free(c0array_meta(array));
	}
}


C0String c0_arena_str_dup(C0Arena *arena, C0String str) {
	char *text = NULL;
	if (str.len) {
		text = (char *)c0_arena_alloc(arena, str.len, 1);
		memcpy(text, str.text, str.len);
	}
	C0String res;
	res.text = text;
	res.len = str.len;
	return res;
}
char const *c0_arena_cstr_dup(C0Arena *arena, char const *str) {
	char *text = NULL;
	if (str) {
		usize len = strlen(str);
		text = (char *)c0_arena_alloc(arena, len+1, 1);
		memcpy(text, str, len);
		text[len] = 0;
	}
	return text;
}


static usize c0_align_formula(usize size, usize align) {
	usize result = size + align-1;
	return result - result%align;
}

enum { C0_DEFAULT_MINIMUM_BLOCK_SIZE = 8ll*1024ll*1024ll };

static usize DEFAULT_PAGE_SIZE = 4096;

static C0MemoryBlock *c0_virtual_memory_alloc(usize size);
static void c0_virtual_memory_dealloc(C0MemoryBlock *block);


static usize arena_align_forward_offset(C0Arena *arena, usize alignment) {
	usize alignment_offset = 0;
	usize ptr = (usize)(arena->curr_block->base + arena->curr_block->used);
	usize mask = alignment-1;
	if (ptr & mask) {
		alignment_offset = alignment - (ptr & mask);
	}
	return alignment_offset;
}

void *c0_arena_alloc(C0Arena *arena, usize min_size, usize alignment) {
	// mutex_lock(&arena->mutex);

	usize size = 0;
	if (arena->curr_block != NULL) {
		size = min_size + arena_align_forward_offset(arena, alignment);
	}

	if (arena->curr_block == NULL || (arena->curr_block->used + size) > arena->curr_block->size) {
		size = c0_align_formula(min_size, alignment);
		if (arena->minimum_block_size < C0_DEFAULT_MINIMUM_BLOCK_SIZE) {
			arena->minimum_block_size = C0_DEFAULT_MINIMUM_BLOCK_SIZE;
		}

		usize block_size = size;
		if (block_size < arena->minimum_block_size) {
			block_size = arena->minimum_block_size;
		}

		C0MemoryBlock *new_block = c0_virtual_memory_alloc(block_size);
		new_block->prev = arena->curr_block;
		arena->curr_block = new_block;
	}

	C0MemoryBlock *curr_block = arena->curr_block;
	assert((curr_block->used + size) <= curr_block->size);

	u8 *ptr = curr_block->base + curr_block->used;
	ptr += arena_align_forward_offset(arena, alignment);

	curr_block->used += size;
	assert(curr_block->used <= curr_block->size);

	// mutex_unlock(&arena->mutex);

	// NOTE(bill): memory will be zeroed by default due to virtual memory
	return ptr;
}

void arena_free_all(C0Arena *arena) {
	while (arena->curr_block != NULL) {
		C0MemoryBlock *free_block = arena->curr_block;
		arena->curr_block = free_block->prev;
		c0_virtual_memory_dealloc(free_block);
	}
}


struct C0PlatformMemoryBlock {
	C0MemoryBlock block; // IMPORTANT NOTE: must be at the start
	usize total_size;
	C0PlatformMemoryBlock *prev, *next;
};


static C0Atomic(usize) c0_global_platform_memory_total_usage;
static C0PlatformMemoryBlock c0_global_platform_memory_block_sentinel;

static C0PlatformMemoryBlock *c0_platform_virtual_memory_alloc(isize total_size);
static void c0_platform_virtual_memory_free(C0PlatformMemoryBlock *block);
static void c0_platform_virtual_memory_protect(void *memory, isize size);

#if defined(_WIN32)
	void c0_platform_virtual_memory_init(void) {
		c0_global_platform_memory_block_sentinel.prev = &c0_global_platform_memory_block_sentinel;
		c0_global_platform_memory_block_sentinel.next = &c0_global_platform_memory_block_sentinel;

		SYSTEM_INFO sys_info = {};
		GetSystemInfo(&sys_info);
		usize sys_page_size = sys_info.dwPageSize;
		if (DEFAULT_PAGE_SIZE < sys_page_size) {
			DEFAULT_PAGE_SIZE = sys_page_size;
		}
	}

	static C0PlatformMemoryBlock *c0_platform_virtual_memory_alloc(usize total_size) {
		C0PlatformMemoryBlock *pmblock = (C0PlatformMemoryBlock *)VirtualAlloc(0, total_size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
		if (pmblock == NULL) {
			fprintf(stderr, "Out of Virtual memory, oh no...\n");
			fprintf(stderr, "Requested: %llu bytes\n", (unsigned long long)total_size);
			fprintf(stderr, "Total Usage: %llu bytes\n", (unsigned long long)c0_global_platform_memory_total_usage);
			assert(pmblock != NULL && "Out of Virtual Memory, oh no...");
		}
		c0_global_platform_memory_total_usage += total_size; // @atomic
		return pmblock;
	}
	static void c0_platform_virtual_memory_free(C0PlatformMemoryBlock *block) {
		c0_global_platform_memory_total_usage -= block->total_size; // @atomic
		assert(VirtualFree(block, 0, MEM_RELEASE));
	}
	static void c0_platform_virtual_memory_protect(void *memory, isize size) {
		DWORD old_protect = 0;
		BOOL is_protected = VirtualProtect(memory, size, PAGE_NOACCESS, &old_protect);
		assert(is_protected);
	}
#else
	static void c0_platform_virtual_memory_init(void) {
		c0_global_platform_memory_block_sentinel.prev = &c0_global_platform_memory_block_sentinel;
		c0_global_platform_memory_block_sentinel.next = &c0_global_platform_memory_block_sentinel;

		usize sys_page_size = sysconf(_SC_PAGE_SIZE);
		if (DEFAULT_PAGE_SIZE < sys_page_size) {
			DEFAULT_PAGE_SIZE = sys_page_size;
		}
	}

	static C0PlatformMemoryBlock *c0_platform_virtual_memory_alloc(isize total_size) {
		C0PlatformMemoryBlock *pmblock = (C0PlatformMemoryBlock *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (pmblock == NULL) {
			fprintf(stderr, "Out of Virtual memory, oh no...\n");
			fprintf(stderr, "Requested: %lld bytes\n", (long long)total_size);
			fprintf(stderr, "Total Usage: %lld bytes\n", (long long)c0_global_platform_memory_total_usage);
			assert(pmblock != NULL, "Out of Virtual Memory, oh no...");
		}
		c0_global_platform_memory_total_usage += total_size;
		return pmblock;
	}
	static void c0_platform_virtual_memory_free(C0PlatformMemoryBlock *block) {
		isize size = block->total_size;
		c0_global_platform_memory_total_usage -= size;
		munmap(block, size);
	}
	static void c0_platform_virtual_memory_protect(void *memory, isize size) {
		int err = mprotect(memory, size, PROT_NONE);
		assert(err == 0);
	}
#endif

static C0MemoryBlock *c0_virtual_memory_alloc(usize size) {
	usize const page_size = DEFAULT_PAGE_SIZE;

	usize total_size     = size + sizeof(C0PlatformMemoryBlock);
	usize base_offset    = sizeof(C0PlatformMemoryBlock);
	usize protect_offset = 0;

	bool do_protection = false;
	{ // overflow protection
		usize rounded_size = c0_align_formula(size, page_size);
		total_size     = rounded_size + 2*page_size;
		base_offset    = page_size + rounded_size - size;
		protect_offset = page_size + rounded_size;
		do_protection  = true;
	}

	C0PlatformMemoryBlock *pmblock = c0_platform_virtual_memory_alloc(total_size);
	assert(pmblock != NULL && "Out of Virtual Memory, oh no...");

	pmblock->block.base = (u8 *)pmblock + base_offset;
	// Should be zeroed
	assert(pmblock->block.used == 0);
	assert(pmblock->block.prev == NULL);

	if (do_protection) {
		c0_platform_virtual_memory_protect((u8 *)pmblock + protect_offset, page_size);
	}

	pmblock->block.size = size;
	pmblock->total_size = total_size;

	C0PlatformMemoryBlock *sentinel = &c0_global_platform_memory_block_sentinel;
	// mutex_lock(&global_memory_block_mutex);
	pmblock->next = sentinel;
	pmblock->prev = sentinel->prev;
	pmblock->prev->next = pmblock;
	pmblock->next->prev = pmblock;
	// mutex_unlock(&global_memory_block_mutex);

	return &pmblock->block;
}

static void c0_virtual_memory_dealloc(C0MemoryBlock *block_to_free) {
	C0PlatformMemoryBlock *block = (C0PlatformMemoryBlock *)block_to_free;
	if (block != NULL) {
		// mutex_lock(&global_memory_block_mutex);
		block->prev->next = block->next;
		block->next->prev = block->prev;
		// mutex_unlock(&global_memory_block_mutex);

		c0_platform_virtual_memory_free(block);
	}
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void c0_gen_init(C0Gen *gen) {
	memset(gen, 0, sizeof(*gen));
}

void c0_gen_destroy(C0Gen *gen) {
	arena_free_all(&gen->arena);
}

bool c0_basic_type_is_integer(C0BasicType type) {
	switch (type) {
	case C0Basic_i8:
	case C0Basic_u8:
	case C0Basic_i16:
	case C0Basic_u16:
	case C0Basic_i32:
	case C0Basic_u32:
	case C0Basic_i64:
	case C0Basic_u64:
	case C0Basic_i128:
	case C0Basic_u128:
		return true;
	case C0Basic_f16:
	case C0Basic_f32:
	case C0Basic_f64:
		return false;
	case C0Basic_ptr:
		return false;
	}
	return false;
}
bool c0_basic_type_is_float(C0BasicType type) {
	switch (type) {
	case C0Basic_i8:
	case C0Basic_u8:
	case C0Basic_i16:
	case C0Basic_u16:
	case C0Basic_i32:
	case C0Basic_u32:
	case C0Basic_i64:
	case C0Basic_u64:
	case C0Basic_i128:
	case C0Basic_u128:
		return false;
	case C0Basic_f16:
	case C0Basic_f32:
	case C0Basic_f64:
		return true;
	case C0Basic_ptr:
		return false;
	}
	return false;
}
bool c0_basic_type_is_ptr(C0BasicType type) {
	switch (type) {
	case C0Basic_i8:
	case C0Basic_u8:
	case C0Basic_i16:
	case C0Basic_u16:
	case C0Basic_i32:
	case C0Basic_u32:
	case C0Basic_i64:
	case C0Basic_u64:
	case C0Basic_i128:
	case C0Basic_u128:
		return false;
	case C0Basic_f16:
	case C0Basic_f32:
	case C0Basic_f64:
		return false;
	case C0Basic_ptr:
		return true;
	}
	return false;
}


C0Proc *c0_proc_create(C0Gen *gen, C0String name) {
	C0Arena *arena = &gen->arena;
	C0Proc *p = c0_arena_new(arena, C0Proc);
	assert(p);
	p->arena = arena;
	p->name  = c0_arena_str_dup(p->arena, name);
	return p;
}
C0Instr *c0_instr_create(C0Proc *p, C0InstrKind kind) {
	C0Instr *instr = c0_arena_new(p->arena, C0Instr);
	instr->kind = kind;
	return instr;
}
C0Instr *c0_instr_push(C0Proc *p, C0Instr *instr) {
	usize n = c0array_len(p->nested_blocks);
	if (n > 0) {
		c0array_push(p->nested_blocks[n-1]->nested_instrs, instr);
	} else {
		c0array_push(p->instrs, instr);
	}
	return instr;
}

C0Instr *c0_push_nested_block(C0Proc *p, C0Instr *block) {
	assert(block);
	switch (block->kind) {
	case C0Instr_if:
	case C0Instr_loop:
	case C0Instr_block:
		break;
	default:
		assert(0 && "invalid block kind");
		break;
	}
	c0array_push(p->nested_blocks, block);
	return block;
}

C0Instr *c0_pop_nested_block(C0Proc *p) {
	usize n = c0array_len(p->nested_blocks);
	assert(n > 0);
	C0Instr *block = p->nested_blocks[n-1];
	c0array_pop(p->nested_blocks);
	return block;
}


C0Instr *c0_use(C0Instr *instr) {
	instr->uses++;
	return instr;
}
C0Instr *c0_unuse(C0Instr *instr) {
	assert(instr->uses > 0);
	instr->uses--;
	return instr;
}

C0Instr *c0_push_basic_i8(C0Proc *p, i8 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_i8;
	val->value_i64 = (i64)value;
	return c0_instr_push(p, val);
}
C0Instr *c0_push_basic_u8(C0Proc *p, u8 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_u8;
	val->value_u64 = (u64)value;
	return c0_instr_push(p, val);
}

C0Instr *c0_push_basic_i16(C0Proc *p, i16 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_i16;
	val->value_i64 = (i64)value;
	return c0_instr_push(p, val);
}
C0Instr *c0_push_basic_u16(C0Proc *p, u16 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_u32;
	val->value_u64 = (u64)value;
	return c0_instr_push(p, val);
}

C0Instr *c0_push_basic_i32(C0Proc *p, i32 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_i32;
	val->value_i64 = (i64)value;
	return c0_instr_push(p, val);
}
C0Instr *c0_push_basic_u32(C0Proc *p, u32 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_u32;
	val->value_u64 = (u64)value;
	return c0_instr_push(p, val);
}

C0Instr *c0_push_basic_i64(C0Proc *p, i64 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_i64;
	val->value_i64 = (i64)value;
	return c0_instr_push(p, val);
}
C0Instr *c0_push_basic_u64(C0Proc *p, u64 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_u64;
	val->value_u64 = (u64)value;
	return c0_instr_push(p, val);
}

C0Instr *c0_push_basic_ptr(C0Proc *p, u64 value) {
	C0Instr *val = c0_instr_create(p, C0Instr_decl);
	val->basic_type = C0Basic_ptr;
	val->value_u64 = (u64)value;
	return c0_instr_push(p, val);
}


static void c0_alloc_args(C0Proc *p, C0Instr *instr, isize len) {
	typedef C0Instr *T;
	instr->args_len = len;
	if (len != 0) {
		instr->args = (T *)c0_arena_alloc(p->arena, sizeof(T)*len, alignof(T));
	}

}

C0Instr *c0_push_bin(C0Proc *p, C0InstrKind kind, C0Instr *left, C0Instr *right) {
	assert(left);
	assert(right);
	assert(left->basic_type == right->basic_type);

	C0Instr *bin = c0_instr_create(p, kind);
	bin->basic_type = left->basic_type;

	switch (bin->basic_type) {
	case C0Basic_i8:
	case C0Basic_u8:
	case C0Basic_i16:
	case C0Basic_u16:
	case C0Basic_i32:
	case C0Basic_u32:
	case C0Basic_i64:
	case C0Basic_u64:
	case C0Basic_i128:
	case C0Basic_u128:
		// check
		break;
	case C0Basic_f16:
	case C0Basic_f32:
	case C0Basic_f64:
		// check
		break;
	case C0Basic_ptr:
		// check
		break;
	default:
		assert(0 && "invalid type for c0_instr_bin");
		break;
	}

	c0_alloc_args(p, bin, 2);
	bin->args[0] = c0_use(left);
	bin->args[1] = c0_use(right);
	return c0_instr_push(p, bin);
}

// TODO(bill): remove the macro
#define C0_PUSH_BIN_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *left, C0Instr *right) { \
	return c0_push_bin(p, C0Instr_##name, left, right); \
}

C0_PUSH_BIN_DEF(add);
C0_PUSH_BIN_DEF(sub);
C0_PUSH_BIN_DEF(mul);
C0_PUSH_BIN_DEF(quoi);
C0_PUSH_BIN_DEF(quou);
C0_PUSH_BIN_DEF(remi);
C0_PUSH_BIN_DEF(remu);
C0_PUSH_BIN_DEF(shli);
C0_PUSH_BIN_DEF(shlu);
C0_PUSH_BIN_DEF(shri);
C0_PUSH_BIN_DEF(shru);

C0_PUSH_BIN_DEF(and);
C0_PUSH_BIN_DEF(or);
C0_PUSH_BIN_DEF(xor);
C0_PUSH_BIN_DEF(eq);
C0_PUSH_BIN_DEF(neq);
C0_PUSH_BIN_DEF(lti);
C0_PUSH_BIN_DEF(ltu);
C0_PUSH_BIN_DEF(gti);
C0_PUSH_BIN_DEF(gtu);
C0_PUSH_BIN_DEF(lteqi);
C0_PUSH_BIN_DEF(ltequ);
C0_PUSH_BIN_DEF(gteqi);
C0_PUSH_BIN_DEF(gtequ);

C0_PUSH_BIN_DEF(addf);
C0_PUSH_BIN_DEF(subf);
C0_PUSH_BIN_DEF(mulf);
C0_PUSH_BIN_DEF(divf);
C0_PUSH_BIN_DEF(eqf);
C0_PUSH_BIN_DEF(neqf);
C0_PUSH_BIN_DEF(ltf);
C0_PUSH_BIN_DEF(gtf);
C0_PUSH_BIN_DEF(lteqf);
C0_PUSH_BIN_DEF(gteqf);

C0Instr *c0_push_negf(C0Proc *p, C0Instr *arg) {
	C0Instr *val = c0_instr_create(p, C0Instr_negf);
	c0_alloc_args(p, val, 1);
	val->args[0] = c0_use(arg);
	return c0_instr_push(p, val);
}

C0Instr *c0_push_noti(C0Proc *p, C0Instr *arg) {
	C0Instr *zero = NULL;
	switch (arg->basic_type) {
	case C0Basic_i8:  zero = c0_push_basic_i8(p, 0);
	case C0Basic_u8:  zero = c0_push_basic_u8(p, 0);
	case C0Basic_i16: zero = c0_push_basic_i16(p, 0);
	case C0Basic_u16: zero = c0_push_basic_u16(p, 0);
	case C0Basic_i32: zero = c0_push_basic_i32(p, 0);
	case C0Basic_u32: zero = c0_push_basic_u32(p, 0);
	case C0Basic_i64: zero = c0_push_basic_i64(p, 0);
	case C0Basic_u64: zero = c0_push_basic_u64(p, 0);
	case C0Basic_i128:
	case C0Basic_u128:
		assert(0 && "todo 128 bit integers");
		break;
	default:
		assert(0 && "invalid type to noti");
		break;
	}
	return c0_push_xor(p, arg, zero);
}

C0Instr *c0_push_notb(C0Proc *p, C0Instr *arg) {
	C0Instr *zero = NULL;
	switch (arg->basic_type) {
	case C0Basic_i8:  zero = c0_push_basic_i8(p, 0);
	case C0Basic_u8:  zero = c0_push_basic_u8(p, 0);
	case C0Basic_i16: zero = c0_push_basic_i16(p, 0);
	case C0Basic_u16: zero = c0_push_basic_u16(p, 0);
	case C0Basic_i32: zero = c0_push_basic_i32(p, 0);
	case C0Basic_u32: zero = c0_push_basic_u32(p, 0);
	case C0Basic_i64: zero = c0_push_basic_i64(p, 0);
	case C0Basic_u64: zero = c0_push_basic_u64(p, 0);
	case C0Basic_i128:
	case C0Basic_u128:
		assert(0 && "todo 128 bit integers");
		break;
	default:
		assert(0 && "invalid type to noti");
		break;
	}
	return c0_push_eq(p, arg, zero);
}



C0Instr *c0_push_return(C0Proc *p, C0Instr *arg) {
	C0Instr *ret = c0_instr_create(p, C0Instr_return);
	c0_alloc_args(p, ret, 1);
	ret->args[0] = c0_use(arg);
	return c0_instr_push(p, ret);
}

C0Instr *c0_push_convert(C0Proc *p, C0BasicType type, C0Instr *arg) {
	assert(type != C0Basic_void);
	assert(arg->basic_type != C0Basic_void);
	if (arg->basic_type == type) {
		return arg;
	}
	C0Instr *cvt = c0_instr_create(p, C0Instr_cvt);
	c0_alloc_args(p, cvt, 1);
	cvt->args[0] = c0_use(arg);
	cvt->basic_type = type;
	return c0_instr_push(p, cvt);
}

C0Instr *c0_push_load_basic(C0Proc *p, C0BasicType type, C0Instr *arg) {
	assert(type != C0Basic_void);
	assert(arg->basic_type == C0Basic_ptr);

	C0Instr *instr = c0_instr_create(p, C0Instr_load);
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(arg);
	instr->basic_type = type;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src) {
	assert(dst->basic_type == C0Basic_ptr);

	C0Instr *instr = c0_instr_create(p, C0Instr_store);
	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	return c0_instr_push(p, instr);
}




C0Instr *c0_push_atomic_thread_fence(C0Proc *p) {
	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_thread_fence);
	return c0_instr_push(p, instr);
}
C0Instr *c0_push_atomic_signal_fence(C0Proc *p) {
	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_signal_fence);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_atomic_load_basic(C0Proc *p, C0BasicType type, C0Instr *arg) {
	assert(type != C0Basic_void);
	assert(arg->basic_type == C0Basic_ptr);
	assert(arg->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_load);
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(arg);
	instr->basic_type = type;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_atomic_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src) {
	assert(dst->basic_type == C0Basic_ptr);
	assert(src->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_store);
	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	return c0_instr_push(p, instr);
}


C0Instr *c0_push_atomic_cas(C0Proc *p, C0Instr *obj, C0Instr *expected, C0Instr *desired) {
	assert(obj->basic_type == C0Basic_ptr);
	assert(expected->basic_type == C0Basic_ptr);
	assert(desired->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_cas);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(obj);
	instr->args[1] = c0_use(expected);
	instr->args[2] = c0_use(desired);
	instr->basic_type = desired->basic_type;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_atomic_bin(C0Proc *p, C0InstrKind kind, C0Instr *dst, C0Instr *src) {
	assert(dst->basic_type == C0Basic_ptr);
	assert(src->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, kind);
	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	instr->basic_type = src->basic_type;
	return c0_instr_push(p, instr);
}


// TODO(bill): remove the macro
#define C0_PUSH_ATOMIC_BIN_DEF(name) C0Instr *c0_push_atomic_##name(C0Proc *p, C0Instr *left, C0Instr *right) { \
	return c0_push_atomic_bin(p, C0Instr_atomic_##name, left, right); \
}

C0_PUSH_ATOMIC_BIN_DEF(xchg);
C0_PUSH_ATOMIC_BIN_DEF(add);
C0_PUSH_ATOMIC_BIN_DEF(sub);
C0_PUSH_ATOMIC_BIN_DEF(and);
C0_PUSH_ATOMIC_BIN_DEF(or);
C0_PUSH_ATOMIC_BIN_DEF(xor);


C0Instr *c0_push_memmove(C0Proc *p, C0Instr *dst, C0Instr *src, C0Instr *size) {
	assert(dst->basic_type == C0Basic_ptr);
	assert(src->basic_type == C0Basic_ptr);
	assert(c0_basic_type_is_integer(size->basic_type));

	C0Instr *instr = c0_instr_create(p, C0Instr_memmove);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	instr->args[2] = c0_use(size);
	return c0_instr_push(p, instr);


}
C0Instr *c0_push_memset(C0Proc *p, C0Instr *dst, u8 val, C0Instr *size) {
	assert(dst->basic_type == C0Basic_ptr);
	assert(c0_basic_type_is_integer(size->basic_type));

	C0Instr *instr = c0_instr_create(p, C0Instr_memset);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(c0_push_basic_u8(p, val));
	instr->args[2] = c0_use(size);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_decl_basic(C0Proc *p, C0BasicType type, C0String name) {
	assert(type != C0Basic_void);
	C0Instr *instr = c0_instr_create(p, C0Instr_decl);
	instr->name = name;
	instr->basic_type = type;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_addr_of_decl(C0Proc *p, C0Instr *decl) {
	assert(decl->kind == C0Instr_decl);
	C0Instr *instr = c0_instr_create(p, C0Instr_addr);
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(decl);
	instr->basic_type = C0Basic_ptr;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_select_basic(C0Proc *p, C0Instr *cond, C0Instr *true_case, C0Instr *false_case) {
	assert(c0_basic_type_is_integer(cond->basic_type));

	assert(true_case->basic_type == false_case->basic_type);
	assert(true_case->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_select);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(cond);
	instr->args[1] = c0_use(true_case);
	instr->args[2] = c0_use(false_case);
	instr->basic_type = true_case->basic_type;
	return c0_instr_push(p, instr);
}

static bool c0_is_within_a_loop(C0Proc *p) {
	usize n = c0array_len(p->nested_blocks);
	for (usize i = n-1; i < n; i--) {
		if (p->nested_blocks[i]->kind == C0Instr_loop) {
			return true;
		}
	}
	return false;
}

C0Instr *c0_push_continue(C0Proc *p) {
	assert(c0_is_within_a_loop(p));
	C0Instr *instr = c0_instr_create(p, C0Instr_continue);
	return c0_instr_push(p, instr);
}
C0Instr *c0_push_break(C0Proc *p) {
	assert(c0_is_within_a_loop(p));
	C0Instr *instr = c0_instr_create(p, C0Instr_break);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_goto(C0Proc *p, C0Instr *label) {
	assert(label->kind == C0Instr_label);
	C0Instr *instr = c0_instr_create(p, C0Instr_goto);
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(label);
	return c0_instr_push(p, instr);
}
C0Instr *c0_push_label(C0Proc *p, C0String name) {
	// TODO(bill): make name unique if it isn't
	C0Instr *instr = c0_instr_create(p, C0Instr_label);
	instr->name = c0_arena_str_dup(p->arena, name);
	return c0_instr_push(p, instr);
}


////////////////////////////
// block
////////////////////////////



C0Instr *c0_push_if(C0Proc *p, C0Instr *cond) {
	C0Instr *block = c0_instr_create(p, C0Instr_if);
	c0_alloc_args(p, block, 2); // one for possible else
	block->args_len = 1;
	block->args[0] = c0_use(cond);

	c0_use(block);

	c0_instr_push(p, block);
	c0_push_nested_block(p, block);
	return block;
}

C0Instr *c0_pop_if(C0Proc *p) {
	C0Instr *block = c0_pop_nested_block(p);
	assert(block->kind == C0Instr_if);
	return block;
}


C0Instr *c0_create_block(C0Proc *p) {
	C0Instr *block = c0_instr_create(p, C0Instr_block);
	return block;
}

C0Instr *c0_start_block(C0Proc *p, C0Instr *block) {
	assert(block->kind == C0Instr_block);
	c0_use(block);
	c0_push_nested_block(p, block);
	return block;
}


C0Instr *c0_pop_block(C0Proc *p) {
	C0Instr *block = c0_pop_nested_block(p);
	assert(block->kind == C0Instr_block);
	return block;
}




void c0_push_else_to_if(C0Proc *p, C0Instr *if_stmt, C0Instr *else_stmt) {
	assert(if_stmt->kind == C0Instr_if);
	if_stmt->args_len = 2; // this is already preallocated for an else
	if_stmt->args[1] = c0_use(else_stmt);
	return;
}


//////////////
// printing //
//////////////

void c0_print_indent(usize indent) {
	while (indent --> 0) {
		printf("\t");
	}
}

bool c0_print_instr_type(C0Instr *instr) {
	if (instr->type) {
		assert(0 && "TODO complex type printing");
	} else if (instr->basic_type != C0Basic_void) {
		printf("%s", c0_basic_names[instr->basic_type]);
		return true;
	}
	return false;
}


void c0_print_instr_arg(C0Instr *instr) {
	if (instr->name.len != 0) {
		printf("%.*s", C0PSTR(instr->name));
	} else {
		printf("r%u", instr->id);
	}
}


void c0_print_instr(C0Instr *instr, usize indent, bool ignore_first_identation) {
	assert(instr != NULL);
	if (instr->kind == C0Instr_label) {
		printf("%.*s:;\n", C0PSTR(instr->name));
		return;
	}
	if (!ignore_first_identation) {
		c0_print_indent(indent);
	}

	switch (instr->kind) {
	case C0Instr_continue:
		printf("continue;\n");
		return;
	case C0Instr_break:
		printf("break;\n");
		return;
	case C0Instr_return:
		printf("return");
		if (instr->args_len != 0) {
			assert(instr->args_len == 1);
			printf(" ");
			c0_print_instr_arg(instr->args[0]);
		}
		printf(";\n");
		return;
	case C0Instr_goto:
		assert(instr->args_len == 1);
		assert(instr->args[0]->kind == C0Instr_label);
		printf("goto %.*s;\n", C0PSTR(instr->args[0]->name));
		return;

	case C0Instr_if:
		assert(instr->args_len >= 1);
		printf("if (");
		c0_print_instr_arg(instr->args[0]);
		printf(") {\n");
		for (usize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_print_instr(instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(indent);
		printf("}");
		if (instr->args_len == 2) {
			printf(" else ");
			c0_print_instr(instr->args[1], indent, true);
		}
		printf("\n");
		return;

	case C0Instr_loop:
		printf("for (;;) {\n");
		for (usize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_print_instr(instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(indent);
		printf("}\n");
		return;

	case C0Instr_block:
		printf("{\n");
		for (usize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_print_instr(instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(indent);
		printf("}\n");
		return;
	}

	if (c0_print_instr_type(instr)) {
		printf(" ");
		c0_print_instr_arg(instr);
		printf(" = ");
	}

	i32 byte_size = 8*c0_basic_type_size[instr->basic_type];

	switch (instr->kind) {
	default:
		assert(0 && "unhandled instruction kind");
		break;

	case C0Instr_decl:
		switch (instr->basic_type) {
		case C0Basic_i8:
		case C0Basic_i16:
		case C0Basic_i32:
		case C0Basic_i64:
			printf("%lld", (long long)instr->value_i64);
			break;
		case C0Basic_u8:
		case C0Basic_u16:
		case C0Basic_u32:
		case C0Basic_u64:
			printf("%llu", (unsigned long long)instr->value_u64);
			break;
		case C0Basic_i128:
		case C0Basic_u128:
			assert(0 && "todo 128 bit integers");
			break;
		case C0Basic_f16:
			printf("%u", instr->value_f16);
			break;
		case C0Basic_f32:
			printf("%g", instr->value_f32);
			break;
		case C0Basic_f64:
			printf("%g", instr->value_f64);
			break;
		case C0Basic_ptr:
			printf("%llx", (unsigned long long)instr->value_u64);
			break;
		default:
			printf("{0}");
		}
		printf(";\n");
		return;

	case C0Instr_addr:
		assert(instr->args_len == 1);
		printf("&");
		c0_print_instr_arg(instr->args[0]);
		printf(";\n");
		return;

	case C0Instr_cvt:
		assert(instr->args_len == 1);
		printf("cvt_%s_to_%s", c0_basic_names[instr->args[0]->basic_type], c0_basic_names[instr->basic_type]);
		break;

	case C0Instr_negf:

	case C0Instr_add:
	case C0Instr_sub:
	case C0Instr_mul:
	case C0Instr_quoi:
	case C0Instr_quou:
	case C0Instr_remi:
	case C0Instr_remu:
	case C0Instr_shli:
	case C0Instr_shlu:
	case C0Instr_shri:
	case C0Instr_shru:

	case C0Instr_and:
	case C0Instr_or:
	case C0Instr_xor:
	case C0Instr_eq:
	case C0Instr_neq:
	case C0Instr_lti:
	case C0Instr_ltu:
	case C0Instr_gti:
	case C0Instr_gtu:
	case C0Instr_lteqi:
	case C0Instr_ltequ:
	case C0Instr_gteqi:
	case C0Instr_gtequ:

	case C0Instr_addf:
	case C0Instr_subf:
	case C0Instr_mulf:
	case C0Instr_divf:
	case C0Instr_eqf:
	case C0Instr_neqf:
	case C0Instr_ltf:
	case C0Instr_gtf:
	case C0Instr_lteqf:
	case C0Instr_gteqf:
		printf("%s%d", c0_instr_names[instr->basic_type], byte_size);
		break;

	case C0Instr_atomic_thread_fence:
	case C0Instr_atomic_signal_fence:
	case C0Instr_memmove:
	case C0Instr_memset:
		printf("%s", c0_instr_names[instr->basic_type]);
		break;

	case C0Instr_select:
		assert(instr->args_len == 3);
		printf("(");
		c0_print_instr_arg(instr->args[0]);
		printf(") ? (");
		c0_print_instr_arg(instr->args[1]);
		printf(") : ");
		printf("(");
		c0_print_instr_arg(instr->args[2]);
		printf(");\n");
		return;

	}
	printf("(");
	for (usize i = 0; i < instr->args_len; i++) {
		if (i != 0) {
			printf(", ");
		}
		c0_print_instr_arg(instr->args[i]);
	}
	printf(")");


	printf(";\n");
}
void c0_assign_reg_id(C0Instr *instr, u32 *reg_id_) {
	if (instr->basic_type != C0Basic_void || instr->type != NULL) {
		instr->id = (*reg_id_)++;
	}

	if (instr->nested_instrs) {
		for (usize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_assign_reg_id(instr->nested_instrs[i], reg_id_);
		}
	}
}

void c0_remove_unused(C0Array(C0Instr *) *array) {
	if (!array || !*array) {
		return;
	}
	usize len = c0array_len((*array));
	for (usize i = len-1; i < len; i--) {
		C0Instr *instr = (*array)[i];
		if (instr->nested_instrs) {
			c0_remove_unused(&instr->nested_instrs);
		}
		if (instr->basic_type != C0Basic_void) {
			if (instr->uses == 0) {
				for (usize j = 0; j < instr->args_len; j++) {
					c0_unuse(instr->args[j]);
				}
				c0array_ordered_remove((*array), i);
				continue;
			}
		}
	}
}


void c0_proc_finish(C0Proc *p) {
	c0_remove_unused(&p->instrs);

	u32 reg_id = 0;

	for (usize i = 0; i < c0array_len(p->instrs); i++) {
		c0_assign_reg_id(p->instrs[i], &reg_id);
	}
}

void c0_print_proc(C0Proc *p) {
	printf("i32 %.*s(void) {\n", C0PSTR(p->name));
	for (usize i = 0; i < c0array_len(p->instrs); i++) {
		c0_print_instr(p->instrs[i], 1, false);
	}
	printf("}\n");
}