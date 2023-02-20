#include <stdarg.h> // va_list, va_{start, end}
#include <stdio.h> // vsnprintf
#include <stdlib.h> // abort

#include "c0_backend.h"
#include "c0.h"

// SysV
#if defined(_WIN32)
static const char *REGISTERS[] = { "%rcx", "%rdx", "%r8", "%r9" };
#else
static const char *REGISTERS[] = { "%r8", "%r9", "%r10", "%r11" };
#endif

static int s_reg = 0;

int reg_alloc() {
	for (usize i = 0; i < sizeof(REGISTERS)/sizeof(*REGISTERS); i++) {
		if (s_reg & (1 << i)) continue;
		s_reg |= (1 << i);
		return i;
	}
	abort();
}

void reg_free(int reg) {
	s_reg &= ~(1 << reg);
}

static void c0_printf(C0Array(u8) *buf, char const *fmt, ...) {
	va_list va;
	va_start(va, fmt);
	const usize n = vsnprintf(0, 0, fmt, va) + 1;
	va_end(va);

	const usize old_size = c0_array_len(*buf);
	const usize new_size = old_size + n;

	c0_array_resize(*buf, new_size);

	va_start(va, fmt);
	vsnprintf((char*)&(*buf)[old_size], n, fmt, va);
	va_end(va);

	c0_array_pop(*buf); // Remove NUL
}

int emit_load(C0Array(u8) *buf, int literal) {
	int reg = reg_alloc();
	c0_printf(buf, "\tmovq\t$%d, %s\n", literal, REGISTERS[reg]);
	return reg;
}

int emit_add(C0Array(u8) *buf, int r1, int r2) {
	c0_printf(buf, "\taddq\t%s, %s\n", REGISTERS[r1], REGISTERS[r2]);
	reg_free(r1);
	return r2;
}

int emit_mul(C0Array(u8) *buf, int r1, int r2) {
	c0_printf(buf, "\timulq\t%s, %s\n", REGISTERS[r1], REGISTERS[r2]);
	reg_free(r1);
	return r2;
}

int emit_sub(C0Array(u8) *buf, int r1, int r2) {
	c0_printf(buf, "\tsubq\t%s, %s\n", REGISTERS[r2], REGISTERS[r1]);
	reg_free(r2);
	return r1;
}

int emit_div(C0Array(u8) *buf, int r1, int r2) {
	c0_printf(buf, "\tmovq\t%s, %%rax\n", REGISTERS[r1]);
	c0_printf(buf, "\tcqo\n");
	c0_printf(buf, "\tidivq\t%s\n", REGISTERS[r2]);
	c0_printf(buf, "\tmovq\t%%rax,%s\n", REGISTERS[r1]);
	reg_free(r2);
	return r1;
}

void emit_ret(C0Array(u8) *buf, int r1) {
	c0_printf(buf, "\tmovq\t%s,%%rax\n", REGISTERS[r1]);
	c0_printf(buf, "\tret\n");
}

void emit_print_impl(C0Array(u8) *buf) {
	c0_printf(buf, ".LC0:\n");
	c0_printf(buf, "\t.string \"%%d\\n\"\n");
	c0_printf(buf, "print:\n");
	c0_printf(buf, "\tpushq\t%%rbp\n");
	c0_printf(buf, "\tmovq\t%%rsp, %%rbp\n");
	c0_printf(buf, "\tsubq\t$16, %%rsp\n");
	c0_printf(buf, "\tmovl\t%%edi, -4(%%rbp)\n");
	c0_printf(buf, "\tmovl\t-4(%%rbp), %%eax\n");
	c0_printf(buf, "\tmovl\t%%eax, %%esi\n");
	c0_printf(buf, "\tleaq\t.LC0(%%rip), %rdi\n");
	c0_printf(buf, "\tmovl\t$0, %%eax\n");
	c0_printf(buf, "\tcall\tprintf@PLT\n");
	c0_printf(buf, "\tleave\n");
	c0_printf(buf, "\tret\n\n");
}

void emit_print(C0Array(u8) *buf, int reg) {
	c0_printf(buf, "\tmovq\t%s, %%rdi\n", REGISTERS[reg]);
	c0_printf(buf, "\tcall\tprint\n");
}

int emit_instr(C0Array(u8) *buf, const C0Proc *proc, C0Instr *instr) {
	const usize n_args = c0_array_len(instr->args);
	int left = n_args >= 1 ? instr->args[0]->reg : 4;
	int right = n_args >= 2 ? instr->args[1]->reg : 4;
	switch (instr->kind) {
	case C0Instr_decl:
		return emit_load(buf, (int)instr->value_u64);
	case C0Instr_add_u32:
		return emit_add(buf, left, right);
	case C0Instr_sub_u32:
		return emit_sub(buf, left, right);
	case C0Instr_mul_u32:
		return emit_mul(buf, left, right);
	case C0Instr_quo_u32:
		return emit_div(buf, left, right);
	case C0Instr_call:
		emit_print(buf, instr->args[0]->reg);
		break;
	case C0Instr_return:
		emit_ret(buf, left);
	default:
	}
	return -1;
}

void emit_proc(C0Array(u8) *buf, const C0Proc *proc) {
	const usize n_instrs = c0_array_len(proc->instrs);
	if (n_instrs == 0) return;
	c0_printf(buf, ".global %.*s\n", C0_SFMT(proc->name));
	c0_printf(buf, "%.*s:\n", C0_SFMT(proc->name));
	int reg = 0;
	for (usize i = 0; i < n_instrs; i++) {
		C0Instr *instr = proc->instrs[i];
		instr->reg = emit_instr(buf, proc, proc->instrs[i]);
	}
}

static C0Array(u8) emit(const C0Gen *gen) {
	C0Array(u8) result = 0;
	c0_printf(&result, ".text\n");
	emit_print_impl(&result);
	const usize n_procs = c0_array_len(gen->procs);
	for (usize i = 0; i < n_procs; i++) {
		emit_proc(&result, gen->procs[i]);
	}
	return result;
}

const C0Backend C0_BACKEND_ASM = {
	C0_SLIT("ASM"),
	emit,
};