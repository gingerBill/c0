#include "c0.c"

C0Proc *test_function(C0Gen *gen) {
	C0AggType *agg_i32 = c0_agg_type_basic(gen, C0Basic_i32);
	// C0AggType *agg_u32 = c0_agg_type_basic(gen, C0Basic_u32);

	C0Array(C0AggType *) sig_types = NULL;
	c0array_push(sig_types, agg_i32);

	C0Array(C0String) sig_names = NULL;
	c0array_push(sig_names, C0STR("n"));

	C0Proc *p = c0_proc_create(gen, C0STR("fibonacci"), c0_agg_type_proc(gen, agg_i32, sig_names, sig_types, 0));

	C0Instr *n = p->parameters[0];

	C0Instr *cond = c0_push_lt(p, n, c0_push_basic_i32(p, 2));
	c0_push_if(p, cond);
	{
		c0_push_return(p, c0_push_basic_i32(p, 1));
	}
	c0_pop_if(p);
	{
		C0Instr *call = c0_instr_create(p, C0Instr_call);
		call->call_sig = p->sig;
		call->basic_type = p->sig->proc.ret->basic.type;

		call->call_proc = p;
		c0_alloc_args(p, call, 1);
		call->args[0] = c0_use(c0_push_sub(p, n, c0_push_basic_u32(p, 1)));

		C0Instr *res = c0_push_mul(p, n, c0_instr_push(p, call));
		c0_push_return(p, res);
	}


	return c0_proc_finish(p);
}


int main(int argc, char const **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	c0_platform_virtual_memory_init();
	C0Gen gen = {0};
	c0_gen_init(&gen);

	C0Proc *p = test_function(&gen);
	c0_gen_instructions_print(&gen);
	c0_print_proc(p);

	fflush(stderr);
	fflush(stdout);
	c0_gen_destroy(&gen);
	return 0;
}

#if 0
C0AggType *agg_i32 = c0_agg_type_basic(&gen, C0Basic_i32);
	C0AggType *agg_ptr = c0_agg_type_basic(&gen, C0Basic_ptr);
	C0Array(C0AggType *) sig_types = NULL;
	c0array_push(sig_types, agg_ptr);
	c0array_push(sig_types, agg_i32);
	c0array_push(sig_types, agg_ptr);

	C0Proc *p = c0_proc_create(&gen, C0STR("test_proc"));
	p->sig = c0_agg_type_proc(&gen, agg_i32, NULL, sig_types, 0);

	C0AggType *array_type = c0_agg_type_array(&gen, p->sig, 4);
	array_type = c0_agg_type_array(&gen, array_type, 8);

	C0Instr *decl0 = c0_push_decl_basic(p, C0Basic_i32, C0STR("foo"));
	C0Instr *decl1 = c0_push_decl_agg(p, array_type, C0STR("bar"));
	c0_use(decl1);
	c0_push_store_basic(p, decl0, c0_push_basic_i32(p, 1));

	{

		C0Instr *c = c0_push_addr_of_decl(p, decl0);
		C0Instr *elem = c0_push_index_ptr(p, array_type, c, c0_push_basic_i32(p, 1));
		c0_use(elem);
	}

	C0Instr *x = c0_push_convert(p, C0Basic_i32, decl0);
	C0Instr *w = c0_push_add(p, x, c0_push_basic_i32(p, 2));
	w = c0_push_mul(p, w, c0_push_basic_i32(p, 3));

	c0_push_loop(p);
	if (true) {
		C0Instr *if_stmt = c0_push_if(p, w);
		{
			C0Instr *a = c0_push_add(p, x, w);
			c0_push_if(p, a);
			{
				c0_push_return(p, c0_push_add(p, a, w));
			}
			c0_pop_if(p);
			c0_push_return(p, a);
		}
		c0_pop_if(p);
		C0Instr *else_stmt = c0_block_create(p);
		c0_block_start_else(p, if_stmt, else_stmt);
		{
			c0_push_return(p, c0_push_convert(p, C0Basic_i32, c0_push_convert(p, C0Basic_i16, x)));
		}
		c0_pop_block(p);
	} else {
		c0_push_break(p);
	}
	c0_pop_loop(p);

	// c0_push_return(p, x);

	c0_proc_finish(p);


	c0_gen_instructions_print(&gen);

	c0_print_proc(p);
#endif