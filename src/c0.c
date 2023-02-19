#include <stdlib.h>

#include "c0.h"
#include "c0_logger.h"
#include "c0_allocator.h"

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

i64 c0_basic_type_size(C0Gen *gen, C0BasicType type) {
	i64 size = c0_basic_type_sizes[type];
	if (size < 0) {
		size = (-size) * gen->ptr_size;
	}
	return size;
}

void c0_gen_init(C0Gen *gen) {
	memset(gen, 0, sizeof(*gen));

	gen->ptr_size = 8;
	for (C0BasicType kind = C0Basic_void; kind < C0Basic_COUNT; kind++) {
		C0AggType *t = c0_new(C0AggType);
		t->kind = C0AggType_basic;
		t->basic.type = kind;
		t->size  = c0_basic_type_size(gen, kind);
		t->align = t->size;
		gen->basic_agg[kind] = t;
	}
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

C0AggType *c0_agg_type_basic(C0Gen *gen, C0BasicType type) {
	return gen->basic_agg[type];
}

C0AggType *c0_agg_type_array(C0Gen *gen, C0AggType *elem, usize len) {
	(void)gen;
	C0_ASSERT(len);
	C0AggType *t = c0_new(C0AggType);
	t->kind = C0AggType_array;
	t->array.elem = elem;
	t->array.len = len;
	// TODO(bill): size of the array
	t->size = len * elem->size;
	t->align = elem->align;
	return t;
}

C0AggType *c0_agg_type_proc(C0Gen *gen, C0AggType *ret, C0Array(C0String) names, C0Array(C0AggType *) types, C0ProcFlags flags) {
	C0AggType *t = c0_new(C0AggType);
	t->kind = C0AggType_proc;
	t->size = gen->ptr_size;
	t->align = gen->ptr_size;

	if (ret == NULL) {
		ret = c0_agg_type_basic(gen, C0Basic_void);
	}
	t->proc.ret = ret;
	t->proc.names = names;
	t->proc.types = types;
	t->proc.flags = flags;
	return t;
}

static bool c0_types_equal(C0AggType *a, C0AggType *b);

static bool c0_types_array_equal(C0Array(C0AggType *) a, C0Array(C0AggType *) b) {
	if (a == b) {
		return true;
	}
	if (c0_array_len(a) != c0_array_len(b)) {
		return false;
	}
	const usize n = c0_array_len(a);
	for (usize i = 0; i < n; i++) {
		if (!c0_types_equal(a[i], b[i])) {
			return false;
		}
	}
	return true;
}

static bool c0_strings_equal(C0String a, C0String b) {
	if (a.len != b.len) {
		return false;
	}
	if (a.text == b.text) {
		return true;
	}
	return memcmp(a.text, b.text, a.len) == 0;
}

static bool c0_types_equal(C0AggType *a, C0AggType *b) {
	if (a == b) {
		return true;
	}
	if (a->kind == b->kind) {
		switch (a->kind) {
		case C0AggType_basic:
			return a->basic.type == b->basic.type;
		case C0AggType_array:
			return a->array.len == b->array.len && a->array.elem == b->array.elem;
		case C0AggType_record:
			return c0_strings_equal(a->record.name, b->record.name);
		case C0AggType_proc:
			return c0_types_equal(a->proc.ret, b->proc.ret) &&
			       c0_types_array_equal(a->proc.types, b->proc.types) &&
			       a->proc.flags == b->proc.flags;

		}
	}
	return false;
}

static bool c0_types_agg_basic(C0AggType *a, C0BasicType b) {
	return a && a->kind == C0AggType_basic && c0_basic_unsigned_type[a->basic.type] == c0_basic_unsigned_type[b];
}

static bool c0_types_agg_agg(C0AggType *a, C0AggType *b) {
	if (a == b) {
		return true;
	}
	if (!a) {
		return false;
	}
	if (a->kind != b->kind) {
		return false;
	}
	switch (a->kind) {
	case C0AggType_proc:
		return false;
	case C0AggType_array:
		return a->array.len == b->array.len && c0_types_agg_agg(a->array.elem, b->array.elem);
	case C0AggType_record:
		return false;
	}
	return true;
}

C0Proc *c0_proc_create(C0Gen *gen, C0String name, C0AggType *sig) {
	C0_ASSERT(sig && sig->kind == C0AggType_proc);

	C0Proc *p = c0_new(C0Proc);
	C0_ASSERT(p);

	p->gen = gen;
	p->name = c0_string_copy(name);
	p->sig = sig;

	const usize n = c0_array_len(sig->proc.names);
	if (n) {
		C0_ASSERT(n == c0_array_len(sig->proc.types));
	}
	
	for (usize i = 0; i < n; i++) {
		C0AggType *type = sig->proc.types[i];
		C0String name = sig->proc.names[i];
		if (name.len > 0) {
			C0Instr *instr = c0_instr_create(p, C0Instr_decl);
			instr->name = name;
			if (type->kind == C0AggType_basic) {
				instr->basic_type = type->basic.type;
			} else {
				instr->agg_type = type;
			}

			c0_array_push(p->parameters, instr);
		}
	}

	c0_array_push(gen->procs, p);

	return p;
}

C0Instr *c0_instr_create(C0Proc *p, C0InstrKind kind) {
	(void)p;
	C0Instr *instr = c0_new(C0Instr);
	instr->kind = kind;
	instr->basic_type = c0_instr_ret_type[kind];
	instr->uses = 0;
	return instr;
}

C0Instr *c0_instr_last(C0Proc *p) {
	(void)p;
	C0Array(C0Instr *) instrs = NULL;
	const usize n = c0_array_len(p->nested_blocks);
	if (n) {
		instrs = p->nested_blocks[n-1]->nested_instrs;
	} else {
		instrs = p->instrs;
	}
	if (c0_array_len(instrs) > 0) {
		return c0_array_last(instrs);
	}
	return NULL;
}

static bool c0_is_instruction_any_break(C0Instr *instr, u32 loop_count) {
	if (instr) {
		if (instr->kind == C0Instr_break) {
			return true;
		}
		if (instr->kind == C0Instr_loop) {
			loop_count += 1;
		}

		if (loop_count > 1) {
			return false;
		}

		const usize len = c0_array_len(instr->nested_instrs);
		for (usize i = 0; i < len; i++) {
			if (c0_is_instruction_any_break(instr->nested_instrs[i], loop_count)) {
				return true;
			}
		}
	}
	return false;
}

static bool c0_is_instruction_terminating(C0Instr *instr) {
	if (!instr) {
		return false;
	}
	if (instr->kind == C0Instr_return) {
		return true;
	} else if (instr->kind == C0Instr_unreachable) {
		return true;
	} else if (instr->kind == C0Instr_if) {
		if (c0_array_len(instr->args) != 2) {
			return false;
		}
		bool terminating_if   = false;
		bool terminating_else = false;
		if (c0_array_len(instr->nested_instrs) == 0) {
			return false;
		}
		C0Instr *last_if = c0_array_last(instr->nested_instrs);
		terminating_if = c0_is_instruction_terminating(last_if);
		terminating_else = c0_is_instruction_terminating(instr->args[1]);

		return terminating_if && terminating_else;
	} else if (instr->kind == C0Instr_block) {
		if (c0_array_len(instr->nested_instrs) == 0) {
			return false;
		}
		C0Instr *last = c0_array_last(instr->nested_instrs);
		return c0_is_instruction_terminating(last);
	} else if (instr->kind == C0Instr_loop) {
		if (c0_array_len(instr->nested_instrs) == 0) {
			return true;
		}
		if (c0_is_instruction_any_break(instr, 0)) {
			return false;
		}
		C0Instr *last = c0_array_last(instr->nested_instrs);
		return c0_is_instruction_terminating(last);
	}
	return false;
}

C0Instr *c0_instr_push(C0Proc *p, C0Instr *instr) {
	if (c0_is_instruction_terminating(c0_instr_last(p))) {
		c0_warning("next instruction will never be executed");
		return NULL;
	}

	const usize n = c0_array_len(p->nested_blocks);
	if (n) {
		c0_array_push(p->nested_blocks[n-1]->nested_instrs, instr);
	} else {
		c0_array_push(p->instrs, instr);
	}
	return instr;
}

C0Instr *c0_push_nested_block(C0Proc *p, C0Instr *block) {
	C0_ASSERT(block);
	switch (block->kind) {
	case C0Instr_if:
	case C0Instr_loop:
	case C0Instr_block:
		break;
	default:
		c0_error("invalid block kind");
		break;
	}
	c0_array_push(p->nested_blocks, block);
	return block;
}

C0Instr *c0_pop_nested_block(C0Proc *p) {
	const usize n = c0_array_len(p->nested_blocks);
	C0_ASSERT(n);
	C0Instr *block = p->nested_blocks[n-1];
	c0_array_pop(p->nested_blocks);
	return block;
}

C0Instr *c0_use(C0Instr *instr) {
	instr->uses++;
	return instr;
}

C0Instr *c0_unuse(C0Instr *instr) {
	C0_ASSERT(instr->uses > 0);
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


static void c0_alloc_args(C0Proc *p, C0Instr *instr, usize len) {
	(void)p;
	instr->args = 0;
	c0_array_resize(instr->args, len);
}

C0Instr *c0_push_bin(C0Proc *p, C0InstrKind kind, C0BasicType type, C0Instr *left, C0Instr *right) {
	(void)p;

	C0_ASSERT(left);
	C0_ASSERT(right);
	C0_ASSERT(type != C0Basic_void);
	C0_ASSERT(c0_basic_unsigned_type[left->basic_type] == c0_basic_unsigned_type[right->basic_type]);

	C0Instr *bin = c0_instr_create(p, kind);
	if (type != left->basic_type) {
		bin->basic_type = type;
	}
	c0_alloc_args(p, bin, 2);
	bin->args[0] = c0_use(left);
	bin->args[1] = c0_use(right);
	return c0_instr_push(p, bin);
}

#define C0_PUSH_BIN_INT_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *left, C0Instr *right) { \
	C0_ASSERT(left); \
	C0_ASSERT(right); \
	C0_ASSERT(left->basic_type != C0Basic_void); \
	C0_ASSERT(left->basic_type == right->basic_type); \
	C0_ASSERT(c0_basic_type_is_integer(left->basic_type)); \
	return c0_push_bin(p, C0Instr_##name##_i8 + (left->basic_type - C0Basic_i8), left->basic_type, left, right); \
}

#define C0_PUSH_BIN_UINT_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *left, C0Instr *right) { \
	C0_ASSERT(c0_basic_type_is_integer(left->basic_type)); \
	C0_ASSERT(c0_basic_unsigned_type[left->basic_type] == c0_basic_unsigned_type[right->basic_type]); \
	return c0_push_bin(p, C0Instr_##name##_u8 + c0_basic_unsigned_instr_offset[left->basic_type], left->basic_type, left, right); \
}


C0_PUSH_BIN_UINT_DEF(add);
C0_PUSH_BIN_UINT_DEF(sub);
C0_PUSH_BIN_UINT_DEF(mul);
C0_PUSH_BIN_INT_DEF(quo);
C0_PUSH_BIN_INT_DEF(rem);
C0_PUSH_BIN_INT_DEF(shlc); // masked C-like
C0_PUSH_BIN_INT_DEF(shrc); // masked C-like
C0_PUSH_BIN_INT_DEF(shlo); // Odin-like
C0_PUSH_BIN_INT_DEF(shro); // Odin-like
C0_PUSH_BIN_UINT_DEF(and);
C0_PUSH_BIN_UINT_DEF(or);
C0_PUSH_BIN_UINT_DEF(xor);
C0_PUSH_BIN_UINT_DEF(eq);
C0_PUSH_BIN_UINT_DEF(neq);
C0_PUSH_BIN_INT_DEF(lt);
C0_PUSH_BIN_INT_DEF(gt);
C0_PUSH_BIN_INT_DEF(lteq);
C0_PUSH_BIN_INT_DEF(gteq);

#define C0_PUSH_BIN_FLOAT_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *left, C0Instr *right) { \
	C0_ASSERT(c0_basic_type_is_float(left->basic_type)); \
	C0_ASSERT(left->basic_type == right->basic_type); \
	return c0_push_bin(p, C0Instr_##name##_f16 + (left->basic_type - C0Basic_f16), left->basic_type, left, right); \
}

C0_PUSH_BIN_FLOAT_DEF(addf);
C0_PUSH_BIN_FLOAT_DEF(subf);
C0_PUSH_BIN_FLOAT_DEF(mulf);
C0_PUSH_BIN_FLOAT_DEF(divf);
C0_PUSH_BIN_FLOAT_DEF(eqf);
C0_PUSH_BIN_FLOAT_DEF(neqf);
C0_PUSH_BIN_FLOAT_DEF(ltf);
C0_PUSH_BIN_FLOAT_DEF(gtf);
C0_PUSH_BIN_FLOAT_DEF(lteqf);
C0_PUSH_BIN_FLOAT_DEF(gteqf);


#define C0_PUSH_UN_INT_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *arg) { \
	C0_ASSERT(c0_basic_type_is_integer(arg->basic_type)); \
	C0Instr *val = c0_instr_create(p, C0Instr_##name##_i8 + (arg->basic_type - C0Basic_i8)); \
	c0_alloc_args(p, val, 1); \
	val->args[0] = c0_use(arg); \
	return c0_instr_push(p, val); \
}

#define C0_PUSH_UN_UINT_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *arg) { \
	C0_ASSERT(c0_basic_type_is_integer(arg->basic_type)); \
	C0Instr *val = c0_instr_create(p, C0Instr_##name##_u8 + c0_basic_unsigned_instr_offset[arg->basic_type]); \
	val->basic_type = arg->basic_type; \
	c0_alloc_args(p, val, 1); \
	val->args[0] = c0_use(arg); \
	return c0_instr_push(p, val); \
}

C0_PUSH_UN_UINT_DEF(clz);
C0_PUSH_UN_UINT_DEF(ctz);
C0_PUSH_UN_UINT_DEF(popcnt);

#undef C0_PUSH_UN_INT_DEF

#define C0_PUSH_UN_FLOAT_DEF(name) C0Instr *c0_push_##name(C0Proc *p, C0Instr *arg) { \
	C0_ASSERT(c0_basic_type_is_float(arg->basic_type)); \
	C0Instr *val = c0_instr_create(p, C0Instr_##name##_f16 + (arg->basic_type - C0Basic_f16)); \
	c0_alloc_args(p, val, 1); \
	val->args[0] = c0_use(arg); \
	return c0_instr_push(p, val); \
}

C0_PUSH_UN_FLOAT_DEF(absf);
C0_PUSH_UN_FLOAT_DEF(ceilf);
C0_PUSH_UN_FLOAT_DEF(floorf);
C0_PUSH_UN_FLOAT_DEF(nearestf);
C0_PUSH_UN_FLOAT_DEF(truncf);
C0_PUSH_UN_FLOAT_DEF(sqrtf);

#undef C0_PUSH_UN_FLOAT_DEF


// pseudo-instruction
C0Instr *c0_push_noti(C0Proc *p, C0Instr *arg) {
	C0Instr *zero = NULL;
	switch (arg->basic_type) {
	case C0Basic_i8: 
		zero = c0_push_basic_i8(p, 0);
		break;
	case C0Basic_u8: 
		zero = c0_push_basic_u8(p, 0);
		break;
	case C0Basic_i16:
		zero = c0_push_basic_i16(p, 0);
		break;
	case C0Basic_u16:
		zero = c0_push_basic_u16(p, 0);
		break;
	case C0Basic_i32:
		zero = c0_push_basic_i32(p, 0);
		break;
	case C0Basic_u32:
		zero = c0_push_basic_u32(p, 0);
		break;
	case C0Basic_i64:
		zero = c0_push_basic_i64(p, 0);
		break;
	case C0Basic_u64:
		zero = c0_push_basic_u64(p, 0);
		break;
	case C0Basic_i128:
	case C0Basic_u128:
		c0_error("todo 128 bit integers");
		break;
	default:
		c0_error("invalid type to noti");
		break;
	}
	return c0_push_xor(p, arg, zero);
}

// pseudo-instruction
C0Instr *c0_push_notb(C0Proc *p, C0Instr *arg) {
	C0Instr *zero = NULL;
	switch (arg->basic_type) {
	case C0Basic_i8: 
		zero = c0_push_basic_i8(p, 0);
		break;
	case C0Basic_u8: 
		zero = c0_push_basic_u8(p, 0);
		break;
	case C0Basic_i16:
		zero = c0_push_basic_i16(p, 0);
		break;
	case C0Basic_u16:
		zero = c0_push_basic_u16(p, 0);
		break;
	case C0Basic_i32:
		zero = c0_push_basic_i32(p, 0);
		break;
	case C0Basic_u32:
		zero = c0_push_basic_u32(p, 0);
		break;
	case C0Basic_i64:
		zero = c0_push_basic_i64(p, 0);
		break;
	case C0Basic_u64:
		zero = c0_push_basic_u64(p, 0);
		break;
	case C0Basic_i128:
	case C0Basic_u128:
		c0_error("todo 128 bit integers");
		break;
	default:
		c0_error("invalid type to noti");
		break;
	}
	return c0_push_eq(p, arg, zero);
}

// pseudo-instruction
C0Instr *c0_push_to_bool(C0Proc *p, C0Instr *arg) {
	C0Instr *zero = NULL;
	switch (arg->basic_type) {
	case C0Basic_i8: 
		zero = c0_push_basic_i8(p, 0);
		break;
	case C0Basic_u8: 
		zero = c0_push_basic_u8(p, 0);
		break;
	case C0Basic_i16:
		zero = c0_push_basic_i16(p, 0);
		break;
	case C0Basic_u16:
		zero = c0_push_basic_u16(p, 0);
		break;
	case C0Basic_i32:
		zero = c0_push_basic_i32(p, 0);
		break;
	case C0Basic_u32:
		zero = c0_push_basic_u32(p, 0);
		break;
	case C0Basic_i64:
		zero = c0_push_basic_i64(p, 0);
		break;
	case C0Basic_u64:
		zero = c0_push_basic_u64(p, 0);
		break;
	case C0Basic_i128:
	case C0Basic_u128:
		c0_error("todo 128 bit integers");
		break;
	default:
		c0_error("invalid type to noti");
		break;
	}
	return c0_push_neq(p, arg, zero);
}


C0Instr *c0_push_unreachable(C0Proc *p) {
	C0Instr *ret = c0_instr_create(p, C0Instr_unreachable);
	c0_use(ret);
	return c0_instr_push(p, ret);
}

// TODO(dweiler): In c0_backend_c.c, maybe refactor cdecl to it's own package.
C0String c0_type_to_cdecl(const C0AggType *type, C0String str);

C0Instr *c0_push_return(C0Proc *p, C0Instr *arg) {
	C0Instr *last = c0_instr_last(p);
	if (c0_is_instruction_terminating(last)) {
		c0_warning("return no called after previous returns");
		return NULL;
	}

	C0Instr *ret = c0_instr_create(p, C0Instr_return);
	if (arg != NULL) {
		C0_ASSERT(p->sig);
		if (arg->agg_type) {
			if (!c0_types_agg_agg(p->sig->proc.ret, arg->agg_type)) {
				const C0String cdecl = c0_type_to_cdecl(p->sig->proc.ret, C0STR(""));
				c0_error("mismatching types in return: expected %.*s, got %s\n", C0PSTR(cdecl), c0_basic_names[arg->basic_type]);
			}
		} else if (!c0_types_agg_basic(p->sig->proc.ret, arg->basic_type)) {
			const C0String cdecl = c0_type_to_cdecl(p->sig->proc.ret, C0STR(""));
			c0_error("mismatching types in return: expected %.*s, got %s\n", C0PSTR(cdecl), c0_basic_names[arg->basic_type]);
		}
		c0_alloc_args(p, ret, 1);
		ret->args[0] = c0_use(arg);
	} else {
		if (!c0_types_agg_basic(p->sig->proc.ret, C0Basic_void)) {
			c0_error("mismatching types in return: expected void, got %s\n", c0_basic_names[C0Basic_void]);
		}
	}
	return c0_instr_push(p, ret);
}

C0Instr *c0_push_convert(C0Proc *p, C0BasicType type, C0Instr *arg) {
	C0_ASSERT(type != C0Basic_void);
	C0_ASSERT(arg->basic_type != C0Basic_void);
	if (arg->basic_type == type) {
		return arg;
	}
	C0Instr *cvt = c0_instr_create(p, C0Instr_convert);
	c0_alloc_args(p, cvt, 1);
	cvt->args[0] = c0_use(arg);
	cvt->basic_type = type;
	return c0_instr_push(p, cvt);
}
C0Instr *c0_push_reinterpret_basic(C0Proc *p, C0BasicType type, C0Instr *arg) {
	C0_ASSERT(type != C0Basic_void);
	C0_ASSERT(arg->basic_type != C0Basic_void);
	if (arg->basic_type == type) {
		return arg;
	}
	if (c0_basic_type_sizes[type] != c0_basic_type_sizes[arg->basic_type]) {
		c0_error("reinterpret requires both types to be of the same size, %s -> %s", c0_basic_names[arg->basic_type], c0_basic_names[type]);
	}
	C0Instr *rip = c0_instr_create(p, C0Instr_reinterpret);
	c0_alloc_args(p, rip, 1);
	rip->args[0] = c0_use(arg);
	rip->basic_type = type;
	return c0_instr_push(p, rip);
}

C0Instr *c0_push_load_basic(C0Proc *p, C0BasicType type, C0Instr *arg) {
	C0_ASSERT(type != C0Basic_void);
	C0_ASSERT(arg->basic_type == C0Basic_ptr);

	C0InstrKind kind = C0Instr_load_u8;

	switch (type) {
	case C0Basic_i8:
	case C0Basic_u8:
		kind = C0Instr_load_u8;
		break;
	case C0Basic_i16:
	case C0Basic_u16:
		kind = C0Instr_load_u16;
		break;
	case C0Basic_i32:
	case C0Basic_u32:
		kind = C0Instr_load_u32;
		break;
	case C0Basic_i64:
	case C0Basic_u64:
		kind = C0Instr_load_u64;
		break;
	case C0Basic_i128:
	case C0Basic_u128:
		kind = C0Instr_load_u128;
		break;
	case C0Basic_f16:
		kind = C0Instr_load_f16;
		break;
	case C0Basic_f32:
		kind = C0Instr_load_f32;
		break;
	case C0Basic_f64:
		kind = C0Instr_load_f64;
		break;
	case C0Basic_ptr:
		kind = C0Instr_load_ptr;
		break;
	}

	C0Instr *instr = c0_instr_create(p, kind);
	instr->basic_type = type;
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(arg);
	return c0_instr_push(p, instr);
}


C0Instr *c0_push_addr_of_decl(C0Proc *p, C0Instr *decl) {
	C0_ASSERT(decl->kind == C0Instr_decl);
	C0Instr *instr = c0_instr_create(p, C0Instr_addr);
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(decl);
	return c0_instr_push(p, instr);
}
C0Instr *c0_push_index_ptr(C0Proc *p, C0AggType *array_type, C0Instr *array_ptr, C0Instr *index) {
	C0_ASSERT(array_type && array_type->kind == C0AggType_array);
	C0_ASSERT(array_ptr->basic_type == C0Basic_ptr);
	C0_ASSERT(c0_basic_type_is_integer(index->basic_type));

	C0Instr *instr = c0_instr_create(p, C0Instr_index_ptr);
	instr->agg_type = array_type;
	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(array_ptr);
	instr->args[1] = c0_use(index);
	return c0_instr_push(p, instr);
}
C0Instr *c0_push_field_ptr(C0Proc *p, C0AggType *record_type, C0Instr *record_ptr, u32 field_index) {
	C0_ASSERT(record_type && record_type->kind == C0AggType_array);
	C0_ASSERT(record_ptr->basic_type == C0Basic_ptr);

	C0_ASSERT(field_index < c0_array_len(record_type->record.types));

	C0Instr *instr = c0_instr_create(p, C0Instr_field_ptr);
	instr->agg_type = record_type;
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(record_ptr);
	instr->value_u64 = (u64)field_index;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src) {
	if (dst->kind == C0Instr_decl) {
		dst = c0_push_addr_of_decl(p, dst);
	}
	C0_ASSERT(dst->basic_type == C0Basic_ptr);

	C0InstrKind kind = C0Instr_store_u8;
	switch (src->basic_type) {
	case C0Basic_i8:
	case C0Basic_u8:
		kind = C0Instr_store_u8;
		break;
	case C0Basic_i16:
	case C0Basic_u16:
		kind = C0Instr_store_u16;
		break;
	case C0Basic_i32:
	case C0Basic_u32:
		kind = C0Instr_store_u32;
		break;
	case C0Basic_i64:
	case C0Basic_u64:
		kind = C0Instr_store_u64;
		break;
	case C0Basic_i128:
	case C0Basic_u128:
		kind = C0Instr_store_u128;
		break;
	case C0Basic_f16:
		kind = C0Instr_store_f16;
		break;
	case C0Basic_f32:
		kind = C0Instr_store_f32;
		break;
	case C0Basic_f64:
		kind = C0Instr_store_f64;
		break;
	case C0Basic_ptr:
		kind = C0Instr_store_ptr;
		break;
	}

	C0Instr *instr = c0_instr_create(p, kind);
	instr->basic_type = C0Basic_void;

	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	c0_use(instr);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_copy_basic(C0Proc *p, C0Instr *arg) {
	C0_ASSERT(arg->basic_type != C0Basic_void);
	C0Instr *instr = c0_instr_create(p, C0Instr_decl);
	instr->basic_type = arg->basic_type;
	c0_instr_push(p, instr);
	c0_push_store_basic(p, instr, arg);
	return instr;
}

C0Instr *c0_push_unaligned_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src) {
	C0_ASSERT(src->basic_type != C0Basic_void);
	if (dst->kind == C0Instr_decl) {
		C0_ASSERT(dst->basic_type == src->basic_type);
		dst = c0_push_addr_of_decl(p, dst);
	}
	C0_ASSERT(dst->basic_type == C0Basic_ptr);
	i64 size = c0_basic_type_size(p->gen, src->basic_type);
	if (src->kind != C0Instr_decl) {
		src = c0_push_copy_basic(p, src);
	}
	src = c0_push_addr_of_decl(p, src);

	C0Instr *len = c0_push_basic_u32(p, (i32)size);
	return c0_push_memmove(p, dst, src, len);
}

C0Instr *c0_push_volatile_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src) {
	return c0_push_unaligned_store_basic(p, dst, src);
}

C0Instr *c0_push_unaligned_load_basic(C0Proc *p, C0BasicType type, C0Instr *ptr) {
	if (ptr->kind == C0Instr_decl) {
		C0_ASSERT(type == ptr->basic_type);
		ptr = c0_push_addr_of_decl(p, ptr);
	}
	C0_ASSERT(ptr->basic_type == C0Basic_ptr);

	C0Instr *val = c0_push_decl_basic(p, type, C0_LIT(C0String));
	C0Instr *val_ptr = c0_push_addr_of_decl(p, val);
	i64 size = c0_basic_type_size(p->gen, type);
	C0Instr *len = c0_push_basic_u32(p, (i32)size);
	c0_push_memmove(p, val_ptr, ptr, len);
	return val;
}

C0Instr *c0_push_volatile_load_basic(C0Proc *p, C0BasicType type, C0Instr *ptr) {
	return c0_push_unaligned_load_basic(p, type, ptr);
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
	C0_ASSERT(type != C0Basic_void);
	C0_ASSERT(arg->basic_type == C0Basic_ptr);
	C0_ASSERT(arg->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_load_u8 + c0_basic_unsigned_instr_offset[type]);
	instr->basic_type = type;
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(arg);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_atomic_store_basic(C0Proc *p, C0Instr *dst, C0Instr *src) {
	C0_ASSERT(dst->basic_type == C0Basic_ptr);
	C0_ASSERT(src->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_store_u8 +  + c0_basic_unsigned_instr_offset[src->basic_type]);
	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_atomic_cas(C0Proc *p, C0Instr *obj, C0Instr *expected, C0Instr *desired) {
	C0_ASSERT(obj->basic_type == C0Basic_ptr);
	C0_ASSERT(expected->basic_type == C0Basic_ptr);
	C0_ASSERT(desired->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_atomic_cas_u8 + c0_basic_unsigned_instr_offset[desired->basic_type]);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(obj);
	instr->args[1] = c0_use(expected);
	instr->args[2] = c0_use(desired);
	c0_use(instr);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_atomic_bin(C0Proc *p, C0InstrKind kind, C0Instr *dst, C0Instr *src) {
	C0_ASSERT(dst->basic_type == C0Basic_ptr);
	C0_ASSERT(src->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, kind);
	c0_alloc_args(p, instr, 2);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	c0_use(instr);
	return c0_instr_push(p, instr);
}

C0_PUSH_BIN_UINT_DEF(atomic_xchg);
C0_PUSH_BIN_UINT_DEF(atomic_add);
C0_PUSH_BIN_UINT_DEF(atomic_sub);
C0_PUSH_BIN_UINT_DEF(atomic_and);
C0_PUSH_BIN_UINT_DEF(atomic_or);
C0_PUSH_BIN_UINT_DEF(atomic_xor);

#undef C0_PUSH_BIN_FLOAT_DEF

#undef C0_PUSH_BIN_INT_DEF
#undef C0_PUSH_BIN_UINT_DEF

C0Instr *c0_push_memmove(C0Proc *p, C0Instr *dst, C0Instr *src, C0Instr *size) {
	C0_ASSERT(dst->basic_type == C0Basic_ptr);
	C0_ASSERT(src->basic_type == C0Basic_ptr);
	C0_ASSERT(c0_basic_type_is_integer(size->basic_type));

	C0Instr *instr = c0_instr_create(p, C0Instr_memmove);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(src);
	instr->args[2] = c0_use(size);
	c0_use(instr);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_memset(C0Proc *p, C0Instr *dst, u8 val, C0Instr *size) {
	C0_ASSERT(dst->basic_type == C0Basic_ptr);
	C0_ASSERT(c0_basic_type_is_integer(size->basic_type));

	C0Instr *instr = c0_instr_create(p, C0Instr_memset);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(dst);
	instr->args[1] = c0_use(c0_push_basic_u8(p, val));
	instr->args[2] = c0_use(size);
	c0_use(instr);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_call_proc1(C0Proc *p, C0Proc *call_proc, C0Instr *arg0) {
	C0Instr *call = c0_instr_create(p, C0Instr_call);
	call->call_sig = call_proc->sig;
	call->basic_type = call_proc->sig->proc.ret->basic.type;

	call->call_proc = call_proc;
	c0_alloc_args(p, call, 1);
	call->args[0] = c0_use(arg0);

	return c0_instr_push(p, call);
}

C0Instr *c0_push_decl_basic_with_alignment(C0Proc *p, C0BasicType type, C0String name, u32 alignment) {
	C0_ASSERT((alignment & (alignment-1)) == 0);
	C0_ASSERT(type != C0Basic_void);
	C0Instr *instr = c0_instr_create(p, C0Instr_decl);
	instr->name = name;
	instr->basic_type = type;
	instr->alignment = alignment;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_decl_basic(C0Proc *p, C0BasicType type, C0String name) {
	C0_ASSERT(type != C0Basic_void);
	C0Instr *instr = c0_instr_create(p, C0Instr_decl);
	instr->name = name;
	instr->basic_type = type;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_decl_agg_with_alignment(C0Proc *p, C0AggType *type, C0String name, u32 alignment) {
	C0_ASSERT((alignment & (alignment-1)) == 0);
	C0_ASSERT(type);
	if (type->kind == C0AggType_basic) {
		return c0_push_decl_basic_with_alignment(p, type->basic.type, name, alignment);
	}
	C0Instr *instr = c0_instr_create(p, C0Instr_decl);
	instr->name = name;
	instr->agg_type = type;
	instr->alignment = alignment;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_decl_agg(C0Proc *p, C0AggType *type, C0String name) {
	C0_ASSERT(type);
	if (type->kind == C0AggType_basic) {
		return c0_push_decl_basic(p, type->basic.type, name);
	}
	C0Instr *instr = c0_instr_create(p, C0Instr_decl);
	instr->name = name;
	instr->agg_type = type;
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_select_basic(C0Proc *p, C0Instr *cond, C0Instr *true_case, C0Instr *false_case) {
	C0_ASSERT(c0_basic_type_is_integer(cond->basic_type));
	if (c0_basic_type_sizes[cond->basic_type] == 16) {
		cond = c0_push_to_bool(p, cond);
	}

	C0_ASSERT(true_case->basic_type == false_case->basic_type);
	C0_ASSERT(true_case->basic_type != C0Basic_void);

	C0Instr *instr = c0_instr_create(p, C0Instr_select_u8 + c0_basic_unsigned_instr_offset[true_case->basic_type]);
	c0_alloc_args(p, instr, 3);
	instr->args[0] = c0_use(cond);
	instr->args[1] = c0_use(true_case);
	instr->args[2] = c0_use(false_case);
	return c0_instr_push(p, instr);
}

static bool c0_is_within_a_loop(C0Proc *p) {
	const usize n = c0_array_len(p->nested_blocks);
	for (usize i = n - 1; i < n; i--) {
		if (p->nested_blocks[i]->kind == C0Instr_loop) {
			return true;
		}
	}
	return false;
}

C0Instr *c0_push_continue(C0Proc *p) {
	C0_ASSERT(c0_is_within_a_loop(p));
	C0Instr *instr = c0_instr_create(p, C0Instr_continue);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_break(C0Proc *p) {
	C0_ASSERT(c0_is_within_a_loop(p));
	C0Instr *instr = c0_instr_create(p, C0Instr_break);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_goto(C0Proc *p, C0Instr *label) {
	C0_ASSERT(label->kind == C0Instr_label);
	C0Instr *instr = c0_instr_create(p, C0Instr_goto);
	c0_alloc_args(p, instr, 1);
	instr->args[0] = c0_use(label);
	return c0_instr_push(p, instr);
}

C0Instr *c0_push_label(C0Proc *p, C0String name) {
	// TODO(bill): make name unique if it isn't
	C0Instr *instr = c0_instr_create(p, C0Instr_label);
	instr->name = c0_string_copy(name);
	usize n = c0_array_len(p->labels);
	for (usize i = 0; i < n; i++) {
		if (!c0_strings_equal(p->labels[i]->name, name)) {
			c0_error("non-unique label names: %.*s", C0PSTR(name));
		}
	}
	c0_array_push(p->labels, instr);
	return c0_instr_push(p, instr);
}

////////////////////////////
// block
////////////////////////////

C0Instr *c0_push_if(C0Proc *p, C0Instr *cond) {
	C0Instr *block = c0_instr_create(p, C0Instr_if);

	block->args = 0;
	c0_array_resize(block->args, 1);
	//block->args_len = 1;
	block->args[0] = c0_use(cond);
	C0_ASSERT(c0_basic_type_is_integer(cond->basic_type));

	c0_use(block);

	c0_instr_push(p, block);
	c0_push_nested_block(p, block);
	return block;
}

C0Instr *c0_pop_if(C0Proc *p) {
	C0Instr *block = c0_pop_nested_block(p);
	C0_ASSERT(block->kind == C0Instr_if);
	return block;
}

C0Instr *c0_block_create(C0Proc *p) {
	C0Instr *block = c0_instr_create(p, C0Instr_block);
	return block;
}

C0Instr *c0_block_start(C0Proc *p, C0Instr *block) {
	C0_ASSERT(block);
	C0_ASSERT(block->kind == C0Instr_block);
	c0_use(block);
	c0_push_nested_block(p, block);
	return block;
}

C0Instr *c0_block_push_and_start(C0Proc *p, C0Instr *block) {
	C0_ASSERT(block->kind == C0Instr_block);
	c0_use(block);
	c0_push_nested_block(p, block);
	return c0_instr_push(p, block);
}

C0Instr *c0_pop_block(C0Proc *p) {
	C0Instr *block = c0_pop_nested_block(p);
	C0_ASSERT(block->kind == C0Instr_block);
	return block;
}

C0Instr *c0_push_loop(C0Proc *p) {
	C0Instr *block = c0_instr_create(p, C0Instr_loop);
	c0_use(block);
	c0_instr_push(p, block);
	c0_push_nested_block(p, block);
	return block;
}

C0Instr *c0_pop_loop(C0Proc *p) {
	C0Instr *block = c0_pop_nested_block(p);
	C0_ASSERT(block->kind == C0Instr_loop);
	return block;
}

void c0_push_else_to_if(C0Proc *p, C0Instr *if_stmt, C0Instr *else_stmt) {
	(void)p;
	C0_ASSERT(else_stmt);
	C0_ASSERT(if_stmt->kind == C0Instr_if);
	c0_array_resize(if_stmt->args, 2);
	if_stmt->args[1] = c0_use(else_stmt);
	return;
}

void c0_block_start_else(C0Proc *p, C0Instr *if_stmt, C0Instr *else_stmt) {
	c0_block_start(p, else_stmt);
	c0_push_else_to_if(p, if_stmt, else_stmt);
}

void c0_block_else_block(C0Proc *p, C0Instr *if_stmt) {
	C0Instr *else_stmt = c0_block_create(p);
	c0_block_start(p, else_stmt);
	c0_push_else_to_if(p, if_stmt, else_stmt);
}

void c0_pass_remove_unused_instructions(C0Array(C0Instr *) *array) {
	if (!array || !*array) {
		return;
	}

	const usize len = c0_array_len(*array);
	for (usize i = len - 1; i < len; i--) {
		C0Instr *instr = (*array)[i];
		if (instr->nested_instrs) {
			c0_pass_remove_unused_instructions(&instr->nested_instrs);
		}
		if (instr->basic_type != C0Basic_void) {
			if (instr->kind == C0Instr_call) {
				continue;
			}
			if (instr->uses == 0) {
				for (usize j = 0; j < c0_array_len(instr->args); j++) {
					c0_unuse(instr->args[j]);
				}
				c0_array_ordered_remove((*array), i);
				continue;
			}
		} else if (instr->kind == C0Instr_if) {
			if (c0_array_len(instr->nested_instrs) == 0) {
				if (c0_array_len(instr->args) == 1) {
					c0_array_ordered_remove((*array), i);
					continue;
				}
			}
		}
	}
}

void c0_assign_reg_id(C0Instr *instr, u32 *reg_id_) {
	const i32 arg_count = c0_instr_arg_count[instr->kind];
	if (arg_count > 0) {
		C0_ASSERT((i32)c0_array_len(instr->args) == arg_count);
	} else {
		switch (instr->kind) {
		case C0Instr_return:
			C0_ASSERT(c0_array_len(instr->args) == 0 || c0_array_len(instr->args) == 1);
			break;
		case C0Instr_if:
			C0_ASSERT(c0_array_len(instr->args) == 1 || c0_array_len(instr->args) == 2);
			break;
		case C0Instr_call:
			C0_ASSERT(instr->call_sig);
			C0_ASSERT(instr->call_sig->kind == C0AggType_proc);
			C0_ASSERT(c0_array_len(instr->args) == c0_array_len(instr->call_sig->proc.types));
			break;
		}
	}
	if (instr->basic_type != C0Basic_void || instr->agg_type != NULL) {
		instr->id = (*reg_id_)++;
	}

	if (instr->nested_instrs) {
		for (usize i = 0; i < c0_array_len(instr->nested_instrs); i++) {
			c0_assign_reg_id(instr->nested_instrs[i], reg_id_);
		}
	}
	if (instr->kind == C0Instr_if && c0_array_len(instr->args) == 2) {
		c0_assign_reg_id(instr->args[1], reg_id_);
	}
}

void c0_register_instr_to_gen(C0Gen *gen, C0Instr *instr) {
	if (!instr) {
		return;
	}

	gen->instrs_to_generate[instr->kind] = true;
	switch (instr->kind) {
	case C0Instr_convert:
		gen->convert_to_generate[instr->args[0]->basic_type][instr->basic_type] = true;
		break;
	case C0Instr_reinterpret:
		gen->reinterpret_to_generate[instr->args[0]->basic_type][instr->basic_type] = true;
		break;
	}
	if (instr->nested_instrs) {
		for (usize i = 0; i < c0_array_len(instr->nested_instrs); i++) {
			c0_register_instr_to_gen(gen, instr->nested_instrs[i]);
		}
	}
	if (instr->kind == C0Instr_if && c0_array_len(instr->args) == 2) {
		c0_register_instr_to_gen(gen, instr->args[1]);
	}
}

C0Proc *c0_proc_finish(C0Proc *p) {
	C0_ASSERT(p->gen);
	C0_ASSERT(c0_array_len(p->nested_blocks) == 0);

	c0_pass_remove_unused_instructions(&p->instrs);

	C0Instr *last = c0_instr_last(p);
	if (c0_is_instruction_terminating(last)) {
		if (last->kind == C0Instr_if || last->kind == C0Instr_loop) {
			c0_array_push(p->instrs, c0_instr_create(p, C0Instr_unreachable));
		}
	} else if (!c0_types_agg_basic(p->sig->proc.ret, C0Basic_void)) {
		c0_error("procedure missing return statement, expected ??");
	}

	u32 reg_id = 0;

	for (usize i = 0; i < c0_array_len(p->instrs); i++) {
		C0Instr *instr = p->instrs[i];
		c0_assign_reg_id(instr, &reg_id);
		c0_register_instr_to_gen(p->gen, instr);
	}
	return p;
}