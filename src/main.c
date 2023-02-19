#include <stdio.h>

#include "c0.h"
#include "c0_allocator.h"
#include "c0_context.h"
#include "c0_backend.h"

C0Proc *test_factorial(C0Gen *gen) {
	C0AggType *agg_u32 = c0_agg_type_basic(gen, C0Basic_u32);

	C0Array(C0AggType *) sig_types = NULL;
	c0_array_push(sig_types, agg_u32);

	C0Array(C0String) sig_names = NULL;
	c0_array_push(sig_names, C0STR("n"));

	C0Proc *p = c0_proc_create(gen, C0STR("factorial"), c0_agg_type_proc(gen, agg_u32, sig_names, sig_types, 0));

	C0Instr *n = p->parameters[0];

	C0Instr *cond = c0_push_lt(p, n, c0_push_basic_u32(p, 2));
	c0_push_if(p, cond);
	{
		c0_push_return(p, c0_push_basic_u32(p, 1));
	}
	c0_pop_if(p);
	{
		C0Instr *one_below = c0_push_call_proc1(p, p, c0_push_sub(p, n, c0_push_basic_u32(p, 1)));
		C0Instr *res = c0_push_mul(p, n, one_below);
		c0_push_return(p, res);
	}

	return c0_proc_finish(p);
}

C0Proc *test_fibonacci(C0Gen *gen) {
	C0AggType *agg_u32 = c0_agg_type_basic(gen, C0Basic_u32);

	C0Array(C0AggType *) sig_types = NULL;
	c0_array_push(sig_types, agg_u32);

	C0Array(C0String) sig_names = NULL;
	c0_array_push(sig_names, C0STR("n"));

	C0Proc *p = c0_proc_create(gen, C0STR("fibonacci"), c0_agg_type_proc(gen, agg_u32, sig_names, sig_types, 0));

	C0Instr *n = p->parameters[0];

	C0Instr *cond = c0_push_lteq(p, n, c0_push_basic_u32(p, 2));
	c0_push_if(p, cond);
	{
		c0_push_return(p, n);
	}
	c0_pop_if(p);
	{
		C0Instr *a = c0_push_call_proc1(p, p, c0_push_sub(p, n, c0_push_basic_u32(p, 1)));
		C0Instr *b = c0_push_call_proc1(p, p, c0_push_sub(p, n, c0_push_basic_u32(p, 2)));
		C0Instr *res = c0_push_add(p, a, b);
		c0_push_return(p, res);
	}

	return c0_proc_finish(p);
}

int main(void) {
	c0_context = C0_DEFAULT_CONTEXT;

	// Create an arena allocator
	const C0Allocator arena = c0_arena_create(&C0_STDLIB_ALLOCATOR);

	// Set the current context's allocator to the arena. The arena will now
	// be used for all subsequent allocations within C0.
	c0_context.allocator = &arena;

	// Generate some procedures.
	C0Gen gen = {0};
	c0_gen_init(&gen);

	test_factorial(&gen);
	test_fibonacci(&gen);

	C0Array(u8) data = c0_emit(&gen, C0STR("C"));

	c0_array_push(data, 0);

	printf("%s\n", data);

	c0_arena_destroy(&arena);

	return 0;
}
