#include <stdio.h>

#include "c0.h"
#include "c0_print.h"
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

void c0_printf(C0Printer *p, char const *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	if (p->custom_vprintf) {
		p->custom_vprintf(p, fmt, va);
	} else {
		vfprintf(stdout, fmt, va);
	}
	va_end(va);
}

void c0_print_instr_expr(C0Printer *p, C0Instr *instr, usize indent);

void c0_print_indent(C0Printer *p, usize indent) {
	while (indent --> 0) {
		c0_printf(p, "\t");
	}
}

void c0_print_agg_type(C0Printer *p, C0AggType *type, C0String name) {
	switch (type->kind) {
	case C0AggType_basic:
		c0_printf(p, "%s", c0_basic_names[type->basic.type]);
		break;
	case C0AggType_array:
		c0_print_agg_type(p, type->array.elem, C0_LIT(C0String));
		c0_printf(p, " (%.*s)[%lld]", C0PSTR(name), (long long)type->array.len);
		break;
	case C0AggType_record:
		c0_error("TODO record printing");
		break;
	case C0AggType_proc:
		c0_error("TODO proc printing");
		break;
	}
}

bool c0_print_instr_type(C0Printer *p, C0Instr *instr) {
	if (instr->agg_type) {
		switch (instr->agg_type->kind) {
		case C0AggType_basic:
			if (instr->agg_type->basic.type == C0Basic_void) {
				return false;
			}
		}
		C0String empty_name = {0};
		c0_print_agg_type(p, instr->agg_type, empty_name);
		return true;
	} else if (instr->basic_type != C0Basic_void) {
		c0_printf(p, "%s", c0_basic_names[instr->basic_type]);
		return true;
	}
	return false;
}
void c0_print_instr_arg(C0Printer *p, C0Instr *instr, usize indent) {
	if (instr->flags & C0InstrFlag_print_inline) {
		c0_print_instr_expr(p, instr, indent);
		return;
	}
	if (instr->name.len != 0) {
		c0_printf(p, "%.*s", C0PSTR(instr->name));
	} else {
		c0_printf(p, "_C0_%u", instr->id);
	}
}

static char *strf_alloc(usize n) {
	return c0_allocate_uninitialized(n);
}

static char *strf(char const *fmt, ...) {
	char *str = NULL;
	va_list va;
	va_start(va, fmt);
	const usize n = 1 + vsnprintf(NULL, 0, fmt, va);
	va_end(va);

	if (n) {
		str = strf_alloc(n);
		va_start(va, fmt);
		vsnprintf(str, n, fmt, va);
		va_end(va);
	}
	return str;
}

static char const *c0_cdecl_paren(char const *str, char c) {
	return c && c != '[' ? strf("(%s)", str) : str;
}

static char const *c0_string_to_cstr(C0String str) {
	char *c = strf_alloc(str.len + 1);
	memmove(c, str.text, str.len);
	c[str.len] = '\0';
	return c;
}

char *str_buf_printf(C0Array(char) *array, char const *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	const usize n = 1 + vsnprintf(NULL, 0, fmt, va);
	va_end(va);

	const usize old_len = c0_array_len(*array);
	const usize new_len = old_len + n;
	c0_array_resize(*array, new_len);

	va_start(va, fmt);
	vsnprintf(&(*array)[old_len], n, fmt, va);
	va_end(va);
	c0_array_meta(*array)->len -= 1; // ignore NUL

	return *array;
}

static char *c0_type_to_cdecl_internal(C0AggType *type, char const *str, bool ignore_proc_ptr);

char *c0_type_to_cdecl(C0AggType *type, char const *str) {
	return c0_type_to_cdecl_internal(type, str, false);
}

static char *c0_type_to_cdecl_internal(C0AggType *type, char const *str, bool ignore_proc_ptr) {
	switch (type->kind) {
	case C0AggType_basic:
		if (type->basic.type == C0Basic_ptr) {
			return strf("void %s", c0_cdecl_paren(strf("*%s", str), *str));
		} else {
			char const *s = c0_basic_names[type->basic.type];
			return strf("%s%s%s", s, *str ? " " : "", str);
		}
	case C0AggType_array:
		return c0_type_to_cdecl(type->array.elem, c0_cdecl_paren(strf("%s[%llu]", str, (unsigned long long)type->array.len), *str));
	case C0AggType_record:
		C0_ASSERT(type->record.name.len != 0);
		return strf("%.*s", C0PSTR(type->record.name));
	case C0AggType_proc:
		{
			C0Array(char) buf = NULL;
			if (ignore_proc_ptr) {
				str_buf_printf(&buf, "%s(", str);
			} else {
				str_buf_printf(&buf, "(*%s)(", str);
			}
			const usize n = c0_array_len(type->proc.types);
			if (n == 0)  {
				str_buf_printf(&buf, "void)");
			} else {
				const usize name_len = c0_array_len(type->proc.names);
				for (usize i = 0; i < n; i++) {
					C0AggType *pt = type->proc.types[i];
					if (i != 0) {
						str_buf_printf(&buf, ", ");
					}
					if (ignore_proc_ptr && name_len == n) {
						C0String name = type->proc.names[i];
						if (name.len != 0) {
							str_buf_printf(&buf, "%s", c0_type_to_cdecl(pt, c0_string_to_cstr(name)));
							continue;
						}
					}
					str_buf_printf(&buf, "%s", c0_type_to_cdecl(pt, ""));
				}
				if (type->proc.flags & C0ProcFlag_variadic) {
					str_buf_printf(&buf, ", ...");
				}
				str_buf_printf(&buf, ")");
			}
			char *result = c0_type_to_cdecl(type->proc.ret, buf);
			c0_array_delete(buf);
			return result;
		}
	}
	return NULL;
}

static void c0_print_instr_creation(C0Printer *p, C0Instr *instr) {
	if (instr->agg_type && instr->kind != C0Instr_index_ptr && instr->kind != C0Instr_field_ptr) {
		switch (instr->agg_type->kind) {
		case C0AggType_basic:
			if (instr->agg_type->basic.type != C0Basic_void) {
				c0_printf(p, "%s ", c0_basic_names[instr->basic_type]);
				c0_print_instr_arg(p, instr, 0);
				c0_printf(p, " = ");
			}
			return;
		}
		char const *name = NULL;
		if (instr->name.len != 0) {
			name = c0_string_to_cstr(instr->name);
		} else {
			name = strf("_C0_%u", instr->id);
		}
		c0_printf(p, "%s = ", c0_type_to_cdecl(instr->agg_type, name));
	} else if (instr->basic_type != C0Basic_void) {
		c0_printf(p, "%s", c0_basic_names[instr->basic_type]);
		if (instr->basic_type != C0Basic_ptr) {
			c0_printf(p, " ");
		}
		c0_print_instr_arg(p, instr, 0);
		c0_printf(p, " = ");
	}
}

void c0_print_instr_expr(C0Printer *p, C0Instr *instr, usize indent) {
	C0_ASSERT(instr->agg_type != NULL || instr->basic_type != C0Basic_void);
	switch (instr->kind) {
	case C0Instr_invalid:
		c0_error("unhandled instruction kind");
		break;

	case C0Instr_decl:
		switch (instr->basic_type) {
		case C0Basic_i8:
		case C0Basic_i16:
		case C0Basic_i32:
		case C0Basic_i64:
			c0_printf(p, "%lld", (long long)instr->value_i64);
			break;
		case C0Basic_u8:
		case C0Basic_u16:
		case C0Basic_u32:
		case C0Basic_u64:
			c0_printf(p, "%llu", (unsigned long long)instr->value_u64);
			break;
		case C0Basic_i128:
		case C0Basic_u128:
			c0_error("todo 128 bit integers");
			break;
		case C0Basic_f16:
			c0_printf(p, "%u", instr->value_f16);
			break;
		case C0Basic_f32:
			c0_printf(p, "%g", instr->value_f32);
			break;
		case C0Basic_f64:
			c0_printf(p, "%g", instr->value_f64);
			break;
		case C0Basic_ptr:
			c0_printf(p, "%llx", (unsigned long long)instr->value_u64);
			break;
		default:
			c0_printf(p, "{0}");
		}
		return;

	case C0Instr_addr:
		C0_ASSERT(instr->basic_type == C0Basic_ptr);
		C0_ASSERT(c0_array_len(instr->args) == 1);
		c0_printf(p, "_C0_addr(");
		c0_print_instr_arg(p, instr->args[0], indent);
		c0_printf(p, ")");
		return;


	case C0Instr_convert:
		C0_ASSERT(c0_array_len(instr->args) == 1);
		c0_printf(p, "_C0_convert_%s_to_%s(", c0_basic_names[instr->args[0]->basic_type], c0_basic_names[instr->basic_type]);
		c0_print_instr_arg(p, instr->args[0], indent);
		c0_printf(p, ")");
		return;
	case C0Instr_reinterpret:
		C0_ASSERT(c0_array_len(instr->args) == 1);
		c0_printf(p, "_C0_reinterpret_%s_to_%s(", c0_basic_names[instr->args[0]->basic_type], c0_basic_names[instr->basic_type]);
		c0_print_instr_arg(p, instr->args[0], indent);
		c0_printf(p, ")");
		return;

	case C0Instr_atomic_thread_fence:
	case C0Instr_atomic_signal_fence:
	case C0Instr_memmove:
	case C0Instr_memset:
		c0_printf(p, "%s", c0_instr_names[instr->kind]);
		break;

	case C0Instr_select_u8:
	case C0Instr_select_u16:
	case C0Instr_select_u32:
	case C0Instr_select_u64:
	case C0Instr_select_u128:
	case C0Instr_select_f16:
	case C0Instr_select_f32:
	case C0Instr_select_f64:
	case C0Instr_select_ptr:
		C0_ASSERT(c0_array_len(instr->args) == 3);
		c0_print_instr_arg(p, instr->args[0], 0);
		c0_printf(p, " ? ");
		c0_print_instr_arg(p, instr->args[1], 0);
		c0_printf(p, " : ");
		c0_print_instr_arg(p, instr->args[2], 0);
		return;

	case C0Instr_index_ptr:
		C0_ASSERT(c0_array_len(instr->args) == 2);
		c0_printf(p, "_C0_%s(%s, ", c0_instr_names[instr->kind], c0_type_to_cdecl(instr->agg_type->array.elem, ""));
		c0_print_instr_arg(p, instr->args[0], 0);
		c0_printf(p, ", ");
		c0_print_instr_arg(p, instr->args[1], 0);
		c0_printf(p, ")");
		return;
	case C0Instr_field_ptr:
		{
			C0_ASSERT(c0_array_len(instr->args) == 1);
			C0_ASSERT(instr->agg_type && instr->agg_type->kind == C0AggType_record);
			C0_ASSERT(instr->value_u64 < (u64)c0_array_len(instr->agg_type->record.names));
			C0String field_name = instr->agg_type->record.names[instr->value_u64];
			c0_printf(p, "_C0_%s(%s, ", c0_instr_names[instr->kind], c0_type_to_cdecl(instr->agg_type, ""));
			c0_print_instr_arg(p, instr->args[0], 0);
			c0_printf(p, ", %.*s", C0PSTR(field_name));
			c0_printf(p, ")");
		}
		return;

	case C0Instr_call:
		C0_ASSERT(instr->call_proc);
		c0_printf(p, "%.*s", C0PSTR(instr->call_proc->name));
		break;

	default:
		c0_printf(p, "_C0_%s", c0_instr_names[instr->kind]);
		break;
	}

	c0_printf(p, "(");
	bool any_inline = false;
	bool any_call = false;
	if (c0_array_len(instr->args) > 1) {
		for (usize i = 0; i < c0_array_len(instr->args); i++) {
			C0Instr *arg = instr->args[i];
			if (arg->flags & C0InstrFlag_print_inline) {
				any_inline = true;
			}
			if (arg->kind != C0Instr_decl) {
				any_call = true;
			}
		}
	}

	bool do_indent = any_inline && any_call;
	if (do_indent) {
		c0_printf(p, "\n");
	}
	if (do_indent) {
		for (usize i = 0; i < c0_array_len(instr->args); i++) {
			C0Instr *arg = instr->args[i];
			c0_print_indent(p, indent+1);
			c0_print_instr_arg(p, arg, indent+1);
			if (i+1 < c0_array_len(instr->args)) {
				c0_printf(p, ",");
			}
			c0_printf(p, "\n");
		}
	} else {
		for (usize i = 0; i < c0_array_len(instr->args); i++) {
			if (i != 0) {
				c0_printf(p, ", ");
			}
			C0Instr *arg = instr->args[i];
			c0_print_instr_arg(p, arg, indent);
		}
	}
	if (do_indent) {
		c0_print_indent(p, indent);
	}
	c0_printf(p, ")");
}

bool c0_instr_can_be_printed_inline_as_condition(C0Instr *instr) {
	if (instr->uses != 1) {
		return false;
	}
	if (instr->name.len != 0) {
		return false;
	}
	if (instr->alignment != 0) {
		return false;
	}
	if (instr->agg_type == NULL && instr->basic_type == C0Basic_void) {
		return false;
	}
	return true;
}
bool c0_instr_can_be_printed_inline(C0Instr *instr) {
	if (!c0_instr_can_be_printed_inline_as_condition(instr)) {
		return false;
	}
	switch (instr->kind) {
	case C0Instr_decl:
		return true;
	case C0Instr_call:
		return false;
	case C0Instr_convert:
	case C0Instr_reinterpret:
		return true;
	}

	if (C0Instr_clz_u8 <= instr->kind && instr->kind <= C0Instr_gteqf_f64) {
		return true;
	}

	if (C0Instr_select_u8 <= instr->kind && instr->kind <= C0Instr_select_ptr) {
		return true;
	}
	return false;
}
bool c0_instr_print_inline_as_condition(C0Printer *p, C0Instr *instr) {
	if (p->flags & C0PrinterFlag_UseInlineArgs) {
		if (instr->flags & C0InstrFlag_print_inline) {
			// don't bother checking again
			return true;
		}
		if (c0_instr_can_be_printed_inline_as_condition(instr)) {
			instr->flags |= C0InstrFlag_print_inline;
			return true;
		}
	}
	return false;
}


void c0_print_instr(C0Printer *p, C0Instr *instr, usize indent, bool ignore_first_identation) {
	C0_ASSERT(instr != NULL);

	if ((p->flags & C0PrinterFlag_UseInlineArgs) && c0_instr_can_be_printed_inline(instr)) {
		instr->flags |= C0InstrFlag_print_inline;
		return;
	}

	if (instr->kind == C0Instr_label) {
		c0_printf(p, "%.*s:;\n", C0PSTR(instr->name));
		return;
	}
	if (!ignore_first_identation) {
		c0_print_indent(p, indent);
	}

	switch (instr->kind) {
	case C0Instr_continue:
		c0_printf(p, "continue;\n");
		return;
	case C0Instr_break:
		c0_printf(p, "break;\n");
		return;
	case C0Instr_return:
		c0_printf(p, "return");
		if (c0_array_len(instr->args) != 0) {
			C0_ASSERT(c0_array_len(instr->args) == 1);
			c0_printf(p, " ");
			C0Instr *arg = instr->args[0];
			c0_instr_print_inline_as_condition(p, arg);
			c0_print_instr_arg(p, arg, indent);
		}
		c0_printf(p, ";\n");
		return;
	case C0Instr_unreachable:
		c0_printf(p, "_C0_unreachable();\n");
		return;
	case C0Instr_goto:
		C0_ASSERT(c0_array_len(instr->args) == 1);
		C0_ASSERT(instr->args[0]->kind == C0Instr_label);
		c0_printf(p, "goto %.*s;\n", C0PSTR(instr->args[0]->name));
		return;

	case C0Instr_if:
		C0_ASSERT(c0_array_len(instr->args) >= 1);
		c0_printf(p, "if (");
		c0_instr_print_inline_as_condition(p, instr->args[0]);
		c0_print_instr_arg(p, instr->args[0], indent);
		c0_printf(p, ") {\n");
		for (usize i = 0; i < c0_array_len(instr->nested_instrs); i++) {
			c0_print_instr(p, instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(p, indent);
		c0_printf(p, "}");
		if (c0_array_len(instr->args) == 2) {
			c0_printf(p, " else ");
			c0_print_instr(p, instr->args[1], indent, true);
		} else {
			c0_printf(p, "\n");
		}
		return;

	case C0Instr_loop:
		c0_printf(p, "for (;;) {\n");
		for (usize i = 0; i < c0_array_len(instr->nested_instrs); i++) {
			c0_print_instr(p, instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(p, indent);
		c0_printf(p, "}\n");
		return;

	case C0Instr_block:
		c0_printf(p, "{\n");
		for (usize i = 0; i < c0_array_len(instr->nested_instrs); i++) {
			c0_print_instr(p, instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(p, indent);
		c0_printf(p, "}\n");
		return;
	}

	if ((instr->basic_type != C0Basic_void || instr->agg_type) && instr->alignment) {
		c0_printf(p, "alignas(%u) ", instr->alignment);
	}

	c0_print_instr_creation(p, instr);
	c0_print_instr_expr(p, instr, indent);
	c0_printf(p, ";\n");
}

void c0_gen_instructions_print(C0Printer *p, C0Gen *gen) {
	c0_printf(p, "#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 201112L)\n");
	c0_printf(p, "#error C0 requires a C11 compiler\n");
	c0_printf(p, "#endif\n\n");
	c0_printf(p, "#define C0_GENERATED 1\n\n");

	c0_printf(p, "#if defined(_MSC_VER)\n");
	c0_printf(p, "#define C0_FORCE_INLINE __forceinline\n");
	c0_printf(p, "#else\n");
	c0_printf(p, "#define C0_FORCE_INLINE __attribute__((always_inline)) inline\n");
	c0_printf(p, "#endif\n\n");

	c0_printf(p, "#define C0_INSTRUCTION static C0_FORCE_INLINE\n");

	c0_printf(p, "typedef signed   char      i8;\n");
	c0_printf(p, "typedef unsigned char      u8;\n");
	c0_printf(p, "typedef signed   short     i16;\n");
	c0_printf(p, "typedef unsigned short     u16;\n");
	c0_printf(p, "typedef signed   int       i32;\n");
	c0_printf(p, "typedef unsigned int       u32;\n");
	c0_printf(p, "typedef signed   long long i64;\n");
	c0_printf(p, "typedef unsigned long long u64;\n");
	if (gen->endian == C0Endian_big) {
		c0_printf(p, "typedef struct i128 { u64 hi; u64 lo; } i128;\n");
		c0_printf(p, "typedef struct u128 { u64 hi; u64 lo; } u128;\n");
	} else {
		c0_printf(p, "typedef struct i128 { u64 lo; u64 hi; } i128;\n");
		c0_printf(p, "typedef struct u128 { u64 lo; u64 hi; } u128;\n");
	}
	c0_printf(p, "typedef unsigned short     f16;\n");
	c0_printf(p, "typedef float              f32;\n");
	c0_printf(p, "typedef double             f64;\n");

	c0_printf(p, "\n");

	if (gen->instrs_to_generate[C0Instr_memmove] || gen->instrs_to_generate[C0Instr_memset]) {
		c0_printf(p, "#include <string.h>\n");
	}

	if (gen->instrs_to_generate[C0Instr_unreachable]) {
		char const *name = c0_instr_names[C0Instr_unreachable];
		c0_printf(p, "C0_INSTRUCTION _Noreturn void _C0_%s(void) {\n", name);
		c0_printf(p, "#if defined(_MSC_VER)\n");
		c0_printf(p, "\t__assume(false);\n");
		c0_printf(p, "#else\n");
		c0_printf(p, "\t__builtin_unreachable();\n");
		c0_printf(p, "#endif\n");
		c0_printf(p, "}\n\n");
	}

	if (gen->instrs_to_generate[C0Instr_addr]) {
		c0_printf(p, "#define _C0_addr(x) (void *)(&(x))\n\n");
	}

	if (gen->instrs_to_generate[C0Instr_index_ptr]) {
		c0_printf(p, "#define _C0_%s(ELEM_TYPE, ptr, index) (void *)&((ELEM_TYPE *)(ptr))[index]\n\n", c0_instr_names[C0Instr_index_ptr]);
	}
	if (gen->instrs_to_generate[C0Instr_field_ptr]) {
		c0_printf(p, "#define _C0_%s(RECORD_TYPE, ptr, field) (void *)&(((RECORD_TYPE *)(ptr))->field\n\n", c0_instr_names[C0Instr_field_ptr]);
	}

	static char const *masks[17] = {};
	masks[1] = "0xff";
	masks[2] = "0xffff";
	masks[4] = "0xffffffff";
	masks[8] = "0xffffffffffffffff";
	masks[16] = "(u128){0xffffffffffffffff, 0xffffffffffffffff}";

	static char const *shift_masks[17] = {};
	shift_masks[1] = "0x7";
	shift_masks[2] = "0xf";
	shift_masks[4] = "0x1f";
	shift_masks[8] = "0x3f";
	shift_masks[16] = "0x7f";


	for (C0InstrKind kind = 1; kind < C0Instr_memmove; kind++) {
		if (gen->instrs_to_generate[kind]) {
			C0BasicType type = c0_instr_arg_type[kind];
			C0BasicType ret = c0_instr_ret_type[kind];
			C0BasicType unsigned_type = c0_basic_unsigned_type[type];

			// Allow for widening
			switch (unsigned_type) {
			case C0Basic_u32:
				if (gen->ptr_size == 4) {
					break;
				}
				/*fallthrough*/
			case C0Basic_u8:
			case C0Basic_u16:
				if (gen->ptr_size == 8) {
					unsigned_type = C0Basic_u64;
				} else if (gen->ptr_size == 4) {
					unsigned_type = C0Basic_u32;
				}
				break;
			}
			char const *ts   = c0_basic_names[type];
			char const *rs   = c0_basic_names[ret];
			char const *uts  = c0_basic_names[unsigned_type];
			i32 bytes        = c0_basic_type_sizes[type];
			i32 bits         = 8*bytes;
			char const *name = c0_instr_names[kind];
			if (bytes == 16) {
				switch (kind) {
				case C0Instr_load_u128:
				case C0Instr_store_u128:
					// trivial calls
					break;

				case C0Instr_clz_u128:
				case C0Instr_ctz_u128:
				case C0Instr_popcnt_u128:
					c0_error("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				case C0Instr_abs_i128:
				case C0Instr_add_u128:
				case C0Instr_sub_u128:
				case C0Instr_mul_u128:
				case C0Instr_quo_i128:
				case C0Instr_quo_u128:
				case C0Instr_rem_i128:
				case C0Instr_rem_u128:
				case C0Instr_shlc_i128:
				case C0Instr_shlc_u128:
				case C0Instr_shrc_i128:
				case C0Instr_shrc_u128:
				case C0Instr_shlo_i128:
				case C0Instr_shlo_u128:
				case C0Instr_shro_i128:
				case C0Instr_shro_u128:
					c0_error("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				case C0Instr_and_u128:
				case C0Instr_or_u128:
				case C0Instr_xor_u128:
					c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
					c0_printf(p, "\t%s x;\n", rs);
					c0_printf(p, "\tx.lo = a.lo %s b.lo;\n", c0_instr_symbols[kind]);
					c0_printf(p, "\tx.hi = a.hi %s b.hi;\n", c0_instr_symbols[kind]);
					c0_printf(p, "\t return x;\n");
					c0_printf(p, "}\n\n");
					continue;
				case C0Instr_eq_u128:
					c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
					c0_printf(p, "\treturn (%s)((a.lo == b.lo) & (a.hi == b.hi));\n", rs);
					c0_printf(p, "}\n\n");
					continue;
				case C0Instr_neq_u128:
					c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
					c0_printf(p, "\treturn (%s)((a.lo != b.lo) | (a.hi != b.hi));\n", rs);
					c0_printf(p, "}\n\n");
					continue;
				case C0Instr_lt_i128:
				case C0Instr_lt_u128:
				case C0Instr_gt_i128:
				case C0Instr_gt_u128:
				case C0Instr_lteq_i128:
				case C0Instr_lteq_u128:
				case C0Instr_gteq_i128:
				case C0Instr_gteq_u128:
					c0_error("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				case C0Instr_min_i128:
				case C0Instr_min_u128:
				case C0Instr_max_i128:
				case C0Instr_max_u128:
					c0_error("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				default:
					c0_error("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				}

			}

			switch (kind) {
			case C0Instr_convert:
			case C0Instr_reinterpret:
			case C0Instr_index_ptr:
			case C0Instr_field_ptr:
				continue;
			}


			if (C0Instr_load_u8 <= kind && kind <= C0Instr_load_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(void *ptr) {\n", rs, name);
				c0_printf(p, "\treturn *(%s *)(ptr);\n", rs);
				c0_printf(p, "}\n\n");
			} else if (C0Instr_store_u8 <= kind && kind <= C0Instr_store_u128) {
				c0_printf(p, "C0_INSTRUCTION void _C0_%s(void *dst, %s src) {\n", name, ts);
				c0_printf(p, "\t*(%s *)(dst) = src;\n", ts);
				c0_printf(p, "}\n\n");
			} else if (C0Instr_clz_u8 <= kind && kind <= C0Instr_popcnt_u128) {
				c0_error("TODO: generate %s", c0_instr_names[kind]);
			} else if (C0Instr_abs_i8 <= kind && kind <= C0Instr_abs_i128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a) {\n", rs, name, ts);
				c0_printf(p, "\treturn (a < 0)  -a : a;\n");
				c0_printf(p, "}\n\n");
			} else if (C0Instr_add_u8 <= kind && kind <= C0Instr_add_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				c0_printf(p, "\t%s x = (%s)a + (%s)b;\n", uts, uts, uts);
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_sub_u8 <= kind && kind <= C0Instr_sub_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				c0_printf(p, "\t%s x = (%s)a - (%s)b;\n", uts, uts, uts);
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_mul_u8 <= kind && kind <= C0Instr_mul_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				c0_printf(p, "\t%s x = (%s)a * (%s)b;\n", uts, uts, uts);
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_quo_i8 <= kind && kind <= C0Instr_quo_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s volatile b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					c0_printf(p, "\ni64 x = (i64)a / (i64)b;\n");
				} else {
					c0_printf(p, "\nu64 x = (u64)a / (u64)b;\n");
				}
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_rem_i8 <= kind && kind <= C0Instr_rem_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s volatile b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					c0_printf(p, "\ni64 x = (i64)a %% (i64)b;\n");
				} else {
					c0_printf(p, "\nu64 x = (u64)a %% (u64)b;\n");
				}
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_shlc_i8 <= kind && kind <= C0Instr_shlc_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					c0_printf(p, "\ni64 x = (i64)a << (i64)((u32)b & %s);\n", shift_masks[bytes]);
				} else {
					c0_printf(p, "\nu64 x = (u64)a << ((u64)b & %s);\n", shift_masks[bytes]);
				}
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_shlo_i8 <= kind && kind <= C0Instr_shlo_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				c0_printf(p, "\ni64 x = b < %d ? ((i64)a << (i64)((u32)b & %s)) : 0;\n", bits, shift_masks[bytes]);
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_shrc_i8 <= kind && kind <= C0Instr_shrc_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					c0_printf(p, "\ni64 x = (i64)a >> (i64)((u64)b & %s);\n", shift_masks[bytes]);
				} else {
					c0_printf(p, "\nu64 x = (u64)a >> ((u64)b & %s);\n", shift_masks[bytes]);
				}
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (C0Instr_shro_i8 <= kind && kind <= C0Instr_shro_u128) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				c0_printf(p, "\ni64 x = b < %d ? ((i64)a >> (i64)((u32)b & %s)) : 0;\n", bits, shift_masks[bytes]);
				char const *mask = masks[bytes];
				if (mask) {
					c0_printf(p, "\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					c0_printf(p, "\treturn (%s)(x);\n", rs);
				}
				c0_printf(p, "}\n\n");
			} else if (c0_instr_arg_count[kind] == 2 && *c0_instr_symbols[kind]) {
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				c0_printf(p, "\t return (%s)(a %s b);\n", rs, c0_instr_symbols[kind]);
				c0_printf(p, "}\n\n");
			} else {
				c0_error("TODO: generate %s", c0_instr_names[kind]);
			}
		}
	}

	for (C0BasicType from = C0Basic_i8; from < C0Basic_COUNT; from++) {
		for (C0BasicType to = C0Basic_i8; to < C0Basic_COUNT; to++) {
			if (from == to) {
				continue;
			}

			// TODO(bill): edge cases for i128, u128, and f16
			if (gen->convert_to_generate[from][to]) {
				char const *name = c0_instr_names[C0Instr_convert];
				char const *from_s = c0_basic_names[from];
				char const *to_s   = c0_basic_names[to];
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s_%s_to_%s(%s a) {\n", to_s, name, from_s, to_s, from_s);
				if (c0_basic_type_sizes[from] > c0_basic_type_sizes[to]) {
					c0_printf(p, "\treturn (%s)(a & %s);\n", to_s, masks[c0_basic_type_sizes[to]]);
				} else {
					c0_printf(p, "\treturn (%s)a;\n", to_s);
				}
				c0_printf(p, "}\n\n");
			} else if (gen->reinterpret_to_generate[from][to]) {
				char const *name = c0_instr_names[C0Instr_reinterpret];
				char const *from_s = c0_basic_names[from];
				char const *to_s   = c0_basic_names[to];
				c0_printf(p, "C0_INSTRUCTION %s _C0_%s_%s_to_%s(%s a) {\n", to_s, name, from_s, to_s, from_s);
				c0_printf(p, "\tunion {%s from; %s to} x;\n", from_s, to_s);
				c0_printf(p, "\tx.from = a;\n");
				c0_printf(p, "\treturn x.to;\n");
				c0_printf(p, "}\n\n");
			}
		}
	}
}

void c0_print_proc(C0Printer *p, C0Proc *procedure) {
	c0_printf(p, "%s {\n", c0_type_to_cdecl_internal(procedure->sig, c0_string_to_cstr(procedure->name), true));
	for (usize i = 0; i < c0_array_len(procedure->instrs); i++) {
		c0_print_instr(p, procedure->instrs[i], 1, false);
	}
	c0_printf(p, "}\n\n");
}