#define C0_USE_INLINE_ARGS false

void c0_print_instr_expr(C0Arena *a, C0Instr *instr, usize indent);

void c0_print_indent(usize indent) {
	while (indent --> 0) {
		printf("\t");
	}
}

void c0_print_agg_type(C0AggType *type, C0String name) {
	switch (type->kind) {
	case C0AggType_basic:
		printf("%s", c0_basic_names[type->basic.type]);
		break;

	case C0AggType_array:
		c0_print_agg_type(type->array.elem, {0});
		printf(" (%.*s)[%lld]", C0PSTR(name), (long long)type->array.len);
		break;
	case C0AggType_record:
		c0_errorf("TODO record printing");
		break;
	case C0AggType_proc:
		c0_errorf("TODO proc printing");
		break;
	}
}


bool c0_print_instr_type(C0Instr *instr) {
	if (instr->agg_type) {
		switch (instr->agg_type->kind) {
		case C0AggType_basic:
			if (instr->agg_type->basic.type == C0Basic_void) {
				return false;
			}
		}
		C0String empty_name = {0};
		c0_print_agg_type(instr->agg_type, empty_name);
		return true;
	} else if (instr->basic_type != C0Basic_void) {
		printf("%s", c0_basic_names[instr->basic_type]);
		return true;
	}
	return false;
}
void c0_print_instr_arg(C0Arena *a, C0Instr *instr, usize indent) {
	if (instr->flags & C0InstrFlag_Print_Inline) {
		c0_print_instr_expr(a, instr, indent);
		return;
	}
	if (instr->name.len != 0) {
		printf("%.*s", C0PSTR(instr->name));
	} else {
		printf("_C0_%u", instr->id);
	}
}

static char *strf_alloc(C0Arena *a, usize n) {
	return (char *)c0_arena_alloc(a, n, 1);
}

static char *strf(C0Arena *a, char const *fmt, ...) {
	char *str = NULL;
	va_list va;
	va_start(va, fmt);
	usize n = 1 + vsnprintf(NULL, 0, fmt, va);
	va_end(va);
	if (n) {
		str = strf_alloc(a, n);
		va_start(va, fmt);
		vsnprintf(str, n, fmt, va);
		va_end(va);
	}
	return str;
}
static char const *c0_cdecl_paren(C0Arena *a, char const *str, char c) {
	return c && c != '[' ? strf(a, "(%s)", str) : str;
}
static char const *c0_string_to_cstr(C0Arena *a, C0String str) {
	char *c = strf_alloc(a, str.len+1);
	memmove(c, str.text, str.len);
	return c;
}

char *str_buf_printf(C0Array(char) *array, char const *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	usize n = 1 + vsnprintf(NULL, 0, fmt, va);
	va_end(va);
	isize old_len = c0array_len(*array);
	isize new_len = old_len + n;
	c0array_resize(*array, new_len);

	va_start(va, fmt);
	vsnprintf(&(*array)[old_len], n, fmt, va);
	va_end(va);
	c0array_meta(*array)->len -= 1; // ignore NUL
	return *array;
}

static char *c0_type_to_cdecl_internal(C0Arena *a, C0AggType *type, char const *str, bool ignore_proc_ptr);
static char *c0_type_to_cdecl(C0Arena *a, C0AggType *type, char const *str) {
	return c0_type_to_cdecl_internal(a, type, str, false);
}
static char *c0_type_to_cdecl_internal(C0Arena *a, C0AggType *type, char const *str, bool ignore_proc_ptr) {
	switch (type->kind) {
	case C0AggType_basic:
		if (type->basic.type == C0Basic_ptr) {
			return strf(a, "void %s", c0_cdecl_paren(a, strf(a, "*%s", str), *str));
		} else {
			char const *s = c0_basic_names[type->basic.type];
			return strf(a, "%s%s%s", s, *str ? " " : "", str);
		}
	case C0AggType_array:
		return c0_type_to_cdecl(a, type->array.elem, c0_cdecl_paren(a, strf(a, "%s[%llu]", str, (unsigned long long)type->array.len), *str));
	case C0AggType_record:
		C0_ASSERT(type->record.name.len != 0);
		return strf(a, "%.*s", C0PSTR(type->record.name));
	case C0AggType_proc:
		{
			C0Array(char) buf = NULL;
			if (ignore_proc_ptr) {
				str_buf_printf(&buf, "%s(", str);
			} else {
				str_buf_printf(&buf, "(*%s)(", str);
			}
			usize n = c0array_len(type->proc.types);
			if (n == 0)  {
				str_buf_printf(&buf, "void)");
			} else {
				usize name_len = c0array_len(type->proc.names);
				for (usize i = 0; i < n; i++) {
					C0AggType *pt = type->proc.types[i];
					if (i != 0) {
						str_buf_printf(&buf, ", ");
					}
					if (ignore_proc_ptr && name_len == n) {
						C0String name = type->proc.names[i];
						if (name.len != 0) {
							str_buf_printf(&buf, "%s", c0_type_to_cdecl(a, pt, c0_string_to_cstr(a, name)));
							continue;
						}
					}
					str_buf_printf(&buf, "%s", c0_type_to_cdecl(a, pt, ""));
				}
				if (type->proc.flags & C0ProcFlag_variadic) {
					str_buf_printf(&buf, ", ...");
				}
				str_buf_printf(&buf, ")");
			}
			char *result = c0_type_to_cdecl(a, type->proc.ret, buf);
			c0array_delete(buf);
			return result;
		}
	}
	C0_PANIC("invalid type");
	return NULL;
}

static void c0_print_instr_creation(C0Arena *a, C0Instr *instr) {
	if (instr->agg_type && instr->kind != C0Instr_index_ptr && instr->kind != C0Instr_field_ptr) {
		switch (instr->agg_type->kind) {
		case C0AggType_basic:
			if (instr->agg_type->basic.type != C0Basic_void) {
				printf("%s ", c0_basic_names[instr->basic_type]);
				c0_print_instr_arg(a, instr, 0);
				printf(" = ");
			}
			return;
		}
		char const *name = NULL;
		if (instr->name.len != 0) {
			name = c0_string_to_cstr(a, instr->name);
		} else {
			name = strf(a, "_C0_%u", instr->id);
		}
		printf("%s = ", c0_type_to_cdecl(a, instr->agg_type, name));
	} else if (instr->basic_type != C0Basic_void) {
		printf("%s", c0_basic_names[instr->basic_type]);
		if (instr->basic_type != C0Basic_ptr) {
			printf(" ");
		}
		c0_print_instr_arg(a, instr, 0);
		printf(" = ");
	}
}

void c0_print_instr_expr(C0Arena *a, C0Instr *instr, usize indent) {
	C0_ASSERT(instr->agg_type != NULL || instr->basic_type != C0Basic_void);
	switch (instr->kind) {
	case C0Instr_invalid:
		c0_errorf("unhandled instruction kind");
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
			c0_errorf("todo 128 bit integers");
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
		return;

	case C0Instr_addr:
		C0_ASSERT(instr->basic_type == C0Basic_ptr);
		C0_ASSERT(instr->args_len == 1);
		printf("_C0_addr(");
		c0_print_instr_arg(a, instr->args[0], indent);
		printf(")");
		return;


	case C0Instr_convert:
		C0_ASSERT(instr->args_len == 1);
		printf("_C0_convert_%s_to_%s(", c0_basic_names[instr->args[0]->basic_type], c0_basic_names[instr->basic_type]);
		c0_print_instr_arg(a, instr->args[0], indent);
		printf(")");
		return;
	case C0Instr_reinterpret:
		C0_ASSERT(instr->args_len == 1);
		printf("_C0_reinterpret_%s_to_%s(", c0_basic_names[instr->args[0]->basic_type], c0_basic_names[instr->basic_type]);
		c0_print_instr_arg(a, instr->args[0], indent);
		printf(")");
		return;

	case C0Instr_atomic_thread_fence:
	case C0Instr_atomic_signal_fence:
	case C0Instr_memmove:
	case C0Instr_memset:
		printf("%s", c0_instr_names[instr->kind]);
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
		C0_ASSERT(instr->args_len == 3);
		c0_print_instr_arg(a, instr->args[0], 0);
		printf(" ? ");
		c0_print_instr_arg(a, instr->args[1], 0);
		printf(" : ");
		c0_print_instr_arg(a, instr->args[2], 0);
		return;

	case C0Instr_index_ptr:
		C0_ASSERT(instr->args_len == 2);
		printf("_C0_%s(%s, ", c0_instr_names[instr->kind], c0_type_to_cdecl(a, instr->agg_type->array.elem, ""));
		c0_print_instr_arg(a, instr->args[0], 0);
		printf(", ");
		c0_print_instr_arg(a, instr->args[1], 0);
		printf(")");
		return;
	case C0Instr_field_ptr:
		{
			C0_ASSERT(instr->args_len == 1);
			C0_ASSERT(instr->agg_type && instr->agg_type->kind == C0AggType_record);
			C0_ASSERT(instr->value_u64 < (u64)c0array_len(instr->agg_type->record.names));
			C0String field_name = instr->agg_type->record.names[instr->value_u64];
			printf("_C0_%s(%s, ", c0_instr_names[instr->kind], c0_type_to_cdecl(a, instr->agg_type, ""));
			c0_print_instr_arg(a, instr->args[0], 0);
			printf(", %.*s", C0PSTR(field_name));
			printf(")");
		}
		return;

	case C0Instr_call:
		C0_ASSERT(instr->call_proc);
		printf("%.*s", C0PSTR(instr->call_proc->name));
		break;

	default:
		printf("_C0_%s", c0_instr_names[instr->kind]);
		break;
	}

	printf("(");
	bool any_inline = false;
	bool any_call = false;
	if (instr->args_len > 1) {
		for (isize i = 0; i < instr->args_len; i++) {
			C0Instr *arg = instr->args[i];
			if (arg->flags & C0InstrFlag_Print_Inline) {
				any_inline = true;
			}
			if (arg->kind != C0Instr_decl) {
				any_call = true;
			}
		}
	}

	bool do_indent = any_inline && any_call;
	if (do_indent) {
		printf("\n");
	}
	if (do_indent) {
		for (isize i = 0; i < instr->args_len; i++) {
			C0Instr *arg = instr->args[i];
			c0_print_indent(indent+1);
			c0_print_instr_arg(a, arg, indent+1);
			if (i+1 < instr->args_len) {
				printf(",");
			}
			printf("\n");
		}
	} else {
		for (isize i = 0; i < instr->args_len; i++) {
			if (i != 0) {
				printf(", ");
			}
			C0Instr *arg = instr->args[i];
			c0_print_instr_arg(a, arg, indent);
		}
	}
	if (do_indent) {
		c0_print_indent(indent);
	}
	printf(")");
}

bool c0_instr_can_be_printed_inline(C0Instr *instr) {
	if (instr->uses != 1) {
		return false;
	}
	if (instr->name.len != 0) {
		return false;
	}
	if (instr->alignment != 0) {
		return false;
	}

	return instr->agg_type != NULL || instr->basic_type != C0Basic_void;
}


void c0_print_instr(C0Arena *a, C0Instr *instr, usize indent, bool ignore_first_identation) {
	C0_ASSERT(instr != NULL);

	if (C0_USE_INLINE_ARGS && c0_instr_can_be_printed_inline(instr)) {
		instr->flags |= C0InstrFlag_Print_Inline;
		return;
	}

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
			C0_ASSERT(instr->args_len == 1);
			printf(" ");
			c0_print_instr_arg(a, instr->args[0], indent);
		}
		printf(";\n");
		return;
	case C0Instr_unreachable:
		printf("_C0_unreachable();\n");
		return;
	case C0Instr_goto:
		C0_ASSERT(instr->args_len == 1);
		C0_ASSERT(instr->args[0]->kind == C0Instr_label);
		printf("goto %.*s;\n", C0PSTR(instr->args[0]->name));
		return;

	case C0Instr_if:
		C0_ASSERT(instr->args_len >= 1);
		printf("if (");
		c0_print_instr_arg(a, instr->args[0], indent);
		printf(") {\n");
		for (isize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_print_instr(a, instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(indent);
		printf("}");
		if (instr->args_len == 2) {
			printf(" else ");
			c0_print_instr(a, instr->args[1], indent, true);
		} else {
			printf("\n");
		}
		return;

	case C0Instr_loop:
		printf("for (;;) {\n");
		for (isize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_print_instr(a, instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(indent);
		printf("}\n");
		return;

	case C0Instr_block:
		printf("{\n");
		for (isize i = 0; i < c0array_len(instr->nested_instrs); i++) {
			c0_print_instr(a, instr->nested_instrs[i], indent+1, false);
		}
		c0_print_indent(indent);
		printf("}\n");
		return;
	}

	if ((instr->basic_type != C0Basic_void || instr->agg_type) && instr->alignment) {
		printf("alignas(%u) ", instr->alignment);
	}

	c0_print_instr_creation(a, instr);
	c0_print_instr_expr(a, instr, indent);
	printf(";\n");
}

void c0_gen_instructions_print(C0Gen *gen) {
	printf("#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 201112L)\n");
	printf("#error C0 requires a C11 compiler\n");
	printf("#endif\n\n");
	printf("#define C0_GENERATED 1\n\n");

	printf("#if defined(_MSC_VER)\n");
	printf("#define C0_FORCE_INLINE __forceinline\n");
	printf("#else\n");
	printf("#define C0_FORCE_INLINE __attribute__((always_inline)) inline\n");
	printf("#endif\n\n");

	printf("#define C0_INSTRUCTION static C0_FORCE_INLINE\n");

	printf("typedef signed   char      i8;\n");
	printf("typedef unsigned char      u8;\n");
	printf("typedef signed   short     i16;\n");
	printf("typedef unsigned short     u16;\n");
	printf("typedef signed   int       i32;\n");
	printf("typedef unsigned int       u32;\n");
	printf("typedef signed   long long i64;\n");
	printf("typedef unsigned long long u64;\n");
	if (gen->endian == C0Endian_big) {
		printf("typedef struct i128 { u64 hi; u64 lo; } i128;\n");
		printf("typedef struct u128 { u64 hi; u64 lo; } u128;\n");
	} else {
		printf("typedef struct i128 { u64 lo; u64 hi; } i128;\n");
		printf("typedef struct u128 { u64 lo; u64 hi; } u128;\n");
	}
	printf("typedef unsigned short     f16;\n");
	printf("typedef float              f32;\n");
	printf("typedef double             f64;\n");

	printf("\n");

	if (gen->instrs_to_generate[C0Instr_memmove] || gen->instrs_to_generate[C0Instr_memset]) {
		printf("#include <string.h>\n");
	}

	if (gen->instrs_to_generate[C0Instr_unreachable]) {
		char const *name = c0_instr_names[C0Instr_unreachable];
		printf("C0_INSTRUCTION _Noreturn void _C0_%s(void) {\n", name);
		printf("#if defined(_MSC_VER)\n");
		printf("\t__assume(false);\n");
		printf("#else\n");
		printf("\t__builtin_unreachable();\n");
		printf("#endif\n");
		printf("}\n\n");
	}

	if (gen->instrs_to_generate[C0Instr_addr]) {
		printf("#define _C0_addr(x) (void *)(&(x))\n\n");
	}

	if (gen->instrs_to_generate[C0Instr_index_ptr]) {
		printf("#define _C0_%s(ELEM_TYPE, ptr, index) (void *)&((ELEM_TYPE *)(ptr))[index]\n\n", c0_instr_names[C0Instr_index_ptr]);
	}
	if (gen->instrs_to_generate[C0Instr_field_ptr]) {
		printf("#define _C0_%s(RECORD_TYPE, ptr, field) (void *)&(((RECORD_TYPE *)(ptr))->field\n\n", c0_instr_names[C0Instr_field_ptr]);
	}

	static char const *masks[16] = {};
	masks[1] = "0xff";
	masks[2] = "0xffff";
	masks[4] = "0xffffffff";
	masks[8] = "0xffffffffffffffff";
	masks[16] = "(u128){0xffffffffffffffff, 0xffffffffffffffff}";

	static char const *shift_masks[16] = {};
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
					c0_errorf("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
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
					c0_errorf("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				case C0Instr_and_u128:
				case C0Instr_or_u128:
				case C0Instr_xor_u128:
					printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
					printf("\t%s x;\n", rs);
					printf("\tx.lo = a.lo %s b.lo;\n", c0_instr_symbols[kind]);
					printf("\tx.hi = a.hi %s b.hi;\n", c0_instr_symbols[kind]);
					printf("\t return x;\n");
					printf("}\n\n");
					continue;
				case C0Instr_eq_u128:
					printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
					printf("\treturn (%s)((a.lo == b.lo) & (a.hi == b.hi));\n", rs);
					printf("}\n\n");
					continue;
				case C0Instr_neq_u128:
					printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
					printf("\treturn (%s)((a.lo != b.lo) | (a.hi != b.hi));\n", rs);
					printf("}\n\n");
					continue;
				case C0Instr_lt_i128:
				case C0Instr_lt_u128:
				case C0Instr_gt_i128:
				case C0Instr_gt_u128:
				case C0Instr_lteq_i128:
				case C0Instr_lteq_u128:
				case C0Instr_gteq_i128:
				case C0Instr_gteq_u128:
					c0_errorf("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				case C0Instr_min_i128:
				case C0Instr_min_u128:
				case C0Instr_max_i128:
				case C0Instr_max_u128:
					c0_errorf("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
					break;
				default:
					c0_errorf("TODO: support 128-bit integers - generate %s", c0_instr_names[kind]);
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
				printf("C0_INSTRUCTION %s _C0_%s(void *ptr) {\n", rs, name);
				printf("\treturn *(%s *)(ptr);\n", rs);
				printf("}\n\n");
			} else if (C0Instr_store_u8 <= kind && kind <= C0Instr_store_u128) {
				printf("C0_INSTRUCTION void _C0_%s(void *dst, %s src) {\n", name, ts);
				printf("\t*(%s *)(dst) = src;\n", ts);
				printf("}\n\n");
			} else if (C0Instr_clz_u8 <= kind && kind <= C0Instr_popcnt_u128) {
				c0_errorf("TODO: generate %s", c0_instr_names[kind]);
			} else if (C0Instr_abs_i8 <= kind && kind <= C0Instr_abs_i128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a) {\n", rs, name, ts);
				printf("\treturn (a < 0)  -a : a;\n");
				printf("}\n\n");
			} else if (C0Instr_add_u8 <= kind && kind <= C0Instr_add_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				printf("\t%s x = (%s)a + (%s)b;\n", uts, uts, uts);
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_sub_u8 <= kind && kind <= C0Instr_sub_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				printf("\t%s x = (%s)a - (%s)b;\n", uts, uts, uts);
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_mul_u8 <= kind && kind <= C0Instr_mul_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				printf("\t%s x = (%s)a * (%s)b;\n", uts, uts, uts);
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_quo_i8 <= kind && kind <= C0Instr_quo_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s volatile b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					printf("\ni64 x = (i64)a / (i64)b;\n");
				} else {
					printf("\nu64 x = (u64)a / (u64)b;\n");
				}
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_rem_i8 <= kind && kind <= C0Instr_rem_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s volatile b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					printf("\ni64 x = (i64)a %% (i64)b;\n");
				} else {
					printf("\nu64 x = (u64)a %% (u64)b;\n");
				}
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_shlc_i8 <= kind && kind <= C0Instr_shlc_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					printf("\ni64 x = (i64)a << (i64)((u32)b & %s);\n", shift_masks[bytes]);
				} else {
					printf("\nu64 x = (u64)a << ((u64)b & %s);\n", shift_masks[bytes]);
				}
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_shlo_i8 <= kind && kind <= C0Instr_shlo_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				printf("\ni64 x = b < %d ? ((i64)a << (i64)((u32)b & %s)) : 0;\n", bits, shift_masks[bytes]);
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_shrc_i8 <= kind && kind <= C0Instr_shrc_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				if (c0_basic_is_signed[type]) {
					printf("\ni64 x = (i64)a >> (i64)((u64)b & %s);\n", shift_masks[bytes]);
				} else {
					printf("\nu64 x = (u64)a >> ((u64)b & %s);\n", shift_masks[bytes]);
				}
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (C0Instr_shro_i8 <= kind && kind <= C0Instr_shro_u128) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				printf("\ni64 x = b < %d ? ((i64)a >> (i64)((u32)b & %s)) : 0;\n", bits, shift_masks[bytes]);
				char const *mask = masks[bytes];
				if (mask) {
					printf("\treturn (%s)(x & %s);\n", rs, mask);
				} else {
					printf("\treturn (%s)(x);\n", rs);
				}
				printf("}\n\n");
			} else if (c0_instr_arg_count[kind] == 2 && *c0_instr_symbols[kind]) {
				printf("C0_INSTRUCTION %s _C0_%s(%s a, %s b) {\n", rs, name, ts, ts);
				printf("\t return (%s)(a %s b);\n", rs, c0_instr_symbols[kind]);
				printf("}\n\n");
			} else {
				c0_errorf("TODO: generate %s", c0_instr_names[kind]);
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
				printf("C0_INSTRUCTION %s _C0_%s_%s_to_%s(%s a) {\n", to_s, name, from_s, to_s, from_s);
				if (c0_basic_type_sizes[from] > c0_basic_type_sizes[to]) {
					printf("\treturn (%s)(a & %s);\n", to_s, masks[c0_basic_type_sizes[to]]);
				} else {
					printf("\treturn (%s)a;\n", to_s);
				}
				printf("}\n\n");
			} else if (gen->reinterpret_to_generate[from][to]) {
				char const *name = c0_instr_names[C0Instr_reinterpret];
				char const *from_s = c0_basic_names[from];
				char const *to_s   = c0_basic_names[to];
				printf("C0_INSTRUCTION %s _C0_%s_%s_to_%s(%s a) {\n", to_s, name, from_s, to_s, from_s);
				printf("\tunion {%s from; %s to} x;\n", from_s, to_s);
				printf("\tx.from = a;\n");
				printf("\treturn x.to;\n");
				printf("}\n\n");
			}
		}
	}
}

void c0_print_proc(C0Proc *p) {
	C0Arena *a = p->arena;
	printf("%s {\n", c0_type_to_cdecl_internal(a, p->sig, c0_string_to_cstr(a, p->name), true));
	for (isize i = 0; i < c0array_len(p->instrs); i++) {
		c0_print_instr(a, p->instrs[i], 1, false);
	}
	printf("}\n\n");
}