#include "c0.c"

int main(int argc, char const **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	c0_platform_virtual_memory_init();
	C0Gen gen = {0};
	c0_gen_init(&gen);

	C0Proc *p = c0_proc_create(&gen, C0STR("test_proc"));

	C0Instr *x = c0_push_convert(p, C0Basic_i32, c0_push_basic_i8(p, 1));
	C0Instr *w = c0_push_add(p, x, c0_push_basic_i32(p, 2));
	w = c0_push_mul(p, w, c0_push_basic_i32(p, 3));
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
	C0Instr *else_stmt = c0_create_block(p);
	c0_push_else_to_if(p, if_stmt, else_stmt);
	c0_start_block(p, else_stmt);
		c0_push_return(p, x);
	c0_pop_block(p);

	c0_push_return(p, w);

	c0_proc_finish(p);

	c0_print_proc(p);

	printf("[DONE]\n");
	fflush(stderr);
	fflush(stdout);
	c0_gen_destroy(&gen);
	return 0;
}