#ifndef C0_INSTR
#define C0_INSTR(...)
#endif

C0_INSTR(invalid, void, void, 0, "")

C0_INSTR(load_u8,    ptr, u8,   1, "")
C0_INSTR(load_u16,   ptr, u16,  1, "")
C0_INSTR(load_u32,   ptr, u32,  1, "")
C0_INSTR(load_u64,   ptr, u64,  1, "")
C0_INSTR(load_u128,  ptr, u128, 1, "")
C0_INSTR(load_f16,   ptr, f16,  1, "")
C0_INSTR(load_f32,   ptr, f32,  1, "")
C0_INSTR(load_f64,   ptr, f64,  1, "")
C0_INSTR(load_ptr,   ptr, ptr,  1, "") 
C0_INSTR(store_u8,   u8,   void, 2, "")
C0_INSTR(store_u16,  u16,  void, 2, "")
C0_INSTR(store_u32,  u32,  void, 2, "")
C0_INSTR(store_u64,  u64,  void, 2, "")
C0_INSTR(store_u128, u128, void, 2, "")
C0_INSTR(store_f16,  f16,  void, 2, "")
C0_INSTR(store_f32,  f32,  void, 2, "")
C0_INSTR(store_f64,  f64,  void, 2, "")
C0_INSTR(store_ptr,  ptr,  void, 2, "")

C0_INSTR(clz_u8,   u8,   u8,      1, "")
C0_INSTR(clz_u16,  u16,  u16,     1, "")
C0_INSTR(clz_u32,  u32,  u32,     1, "")
C0_INSTR(clz_u64,  u64,  u64,     1, "")
C0_INSTR(clz_u128, u128, u128,    1, "")
C0_INSTR(ctz_u8,   u8,   u8,      1, "")
C0_INSTR(ctz_u16,  u16,  u16,     1, "")
C0_INSTR(ctz_u32,  u32,  u32,     1, "")
C0_INSTR(ctz_u64,  u64,  u64,     1, "")
C0_INSTR(ctz_u128, u128, u128,    1, "")
C0_INSTR(popcnt_u8,   u8,   u8,   1, "")
C0_INSTR(popcnt_u16,  u16,  u16,  1, "")
C0_INSTR(popcnt_u32,  u32,  u32,  1, "")
C0_INSTR(popcnt_u64,  u64,  u64,  1, "")
C0_INSTR(popcnt_u128, u128, u128, 1, "")

C0_INSTR(absf_f16,     f16, f16, 1, "")
C0_INSTR(absf_f32,     f32, f32, 1, "")
C0_INSTR(absf_f64,     f64, f64, 1, "")
C0_INSTR(ceilf_f16,    f16, f16, 1, "")
C0_INSTR(ceilf_f32,    f32, f32, 1, "")
C0_INSTR(ceilf_f64,    f64, f64, 1, "")
C0_INSTR(floorf_f16,   f16, f16, 1, "")
C0_INSTR(floorf_f32,   f32, f32, 1, "")
C0_INSTR(floorf_f64,   f64, f64, 1, "")
C0_INSTR(nearestf_f16, f16, f16, 1, "")
C0_INSTR(nearestf_f32, f32, f32, 1, "")
C0_INSTR(nearestf_f64, f64, f64, 1, "")
C0_INSTR(truncf_f16,   f16, f16, 1, "")
C0_INSTR(truncf_f32,   f32, f32, 1, "")
C0_INSTR(truncf_f64,   f64, f64, 1, "")
C0_INSTR(sqrtf_f16,    f16, f16, 1, "")
C0_INSTR(sqrtf_f32,    f32, f32, 1, "")
C0_INSTR(sqrtf_f64,    f64, f64, 1, "")

C0_INSTR(add_u8,   u8,   u8,   2, "")
C0_INSTR(add_u16,  u16,  u16,  2, "")
C0_INSTR(add_u32,  u32,  u32,  2, "")
C0_INSTR(add_u64,  u64,  u64,  2, "")
C0_INSTR(add_u128, u128, u128, 2, "")
C0_INSTR(sub_u8,   u8,   u8,   2, "")
C0_INSTR(sub_u16,  u16,  u16,  2, "")
C0_INSTR(sub_u32,  u32,  u32,  2, "")
C0_INSTR(sub_u64,  u64,  u64,  2, "")
C0_INSTR(sub_u128, u128, u128, 2, "")
C0_INSTR(mul_u8,   u8,   u8,   2, "")
C0_INSTR(mul_u16,  u16,  u16,  2, "")
C0_INSTR(mul_u32,  u32,  u32,  2, "")
C0_INSTR(mul_u64,  u64,  u64,  2, "")
C0_INSTR(mul_u128, u128, u128, 2, "")
C0_INSTR(quo_i8,   i8,   i8,   2, "")
C0_INSTR(quo_u8,   u8,   u8,   2, "")
C0_INSTR(quo_i16,  i16,  i16,  2, "")
C0_INSTR(quo_u16,  u16,  u16,  2, "")
C0_INSTR(quo_i32,  i32,  i32,  2, "")
C0_INSTR(quo_u32,  u32,  u32,  2, "")
C0_INSTR(quo_i64,  i64,  i64,  2, "")
C0_INSTR(quo_u64,  u64,  u64,  2, "")
C0_INSTR(quo_i128, i128, i128, 2, "")
C0_INSTR(quo_u128, u128, u128, 2, "")
C0_INSTR(rem_i8,   i8,   i8,   2, "")
C0_INSTR(rem_u8,   u8,   u8,   2, "")
C0_INSTR(rem_i16,  i16,  i16,  2, "")
C0_INSTR(rem_u16,  u16,  u16,  2, "")
C0_INSTR(rem_i32,  i32,  i32,  2, "")
C0_INSTR(rem_u32,  u32,  u32,  2, "")
C0_INSTR(rem_i64,  i64,  i64,  2, "")
C0_INSTR(rem_u64,  u64,  u64,  2, "")
C0_INSTR(rem_i128, i128, i128, 2, "")
C0_INSTR(rem_u128, u128, u128, 2, "")
/* C-like shifts */
C0_INSTR(shlc_i8,   i8,   i8,   2, "")
C0_INSTR(shlc_u8,   u8,   u8,   2, "")
C0_INSTR(shlc_i16,  i16,  i16,  2, "")
C0_INSTR(shlc_u16,  u16,  u16,  2, "")
C0_INSTR(shlc_i32,  i32,  i32,  2, "")
C0_INSTR(shlc_u32,  u32,  u32,  2, "")
C0_INSTR(shlc_i64,  i64,  i64,  2, "")
C0_INSTR(shlc_u64,  u64,  u64,  2, "")
C0_INSTR(shlc_i128, i128, i128, 2, "")
C0_INSTR(shlc_u128, u128, u128, 2, "")
C0_INSTR(shrc_i8,   i8,   i8,   2, "")
C0_INSTR(shrc_u8,   u8,   u8,   2, "")
C0_INSTR(shrc_i16,  i16,  i16,  2, "")
C0_INSTR(shrc_u16,  u16,  u16,  2, "")
C0_INSTR(shrc_i32,  i32,  i32,  2, "")
C0_INSTR(shrc_u32,  u32,  u32,  2, "")
C0_INSTR(shrc_i64,  i64,  i64,  2, "")
C0_INSTR(shrc_u64,  u64,  u64,  2, "")
C0_INSTR(shrc_i128, i128, i128, 2, "")
C0_INSTR(shrc_u128, u128, u128, 2, "")
/* Odin-like shifts */
C0_INSTR(shlo_i8,   i8,   i8,   2, "")
C0_INSTR(shlo_u8,   u8,   u8,   2, "")
C0_INSTR(shlo_i16,  i16,  i16,  2, "")
C0_INSTR(shlo_u16,  u16,  u16,  2, "")
C0_INSTR(shlo_i32,  i32,  i32,  2, "")
C0_INSTR(shlo_u32,  u32,  u32,  2, "")
C0_INSTR(shlo_i64,  i64,  i64,  2, "")
C0_INSTR(shlo_u64,  u64,  u64,  2, "")
C0_INSTR(shlo_i128, i128, i128, 2, "")
C0_INSTR(shlo_u128, u128, u128, 2, "")
C0_INSTR(shro_i8,   i8,   i8,   2, "")
C0_INSTR(shro_u8,   u8,   u8,   2, "")
C0_INSTR(shro_i16,  i16,  i16,  2, "")
C0_INSTR(shro_u16,  u16,  u16,  2, "")
C0_INSTR(shro_i32,  i32,  i32,  2, "")
C0_INSTR(shro_u32,  u32,  u32,  2, "")
C0_INSTR(shro_i64,  i64,  i64,  2, "")
C0_INSTR(shro_u64,  u64,  u64,  2, "")
C0_INSTR(shro_i128, i128, i128, 2, "")
C0_INSTR(shro_u128, u128, u128, 2, "")

C0_INSTR(and_u8,   u8,   u8,   2, "&")
C0_INSTR(and_u16,  u16,  u16,  2, "&")
C0_INSTR(and_u32,  u32,  u32,  2, "&")
C0_INSTR(and_u64,  u64,  u64,  2, "&")
C0_INSTR(and_u128, u128, u128, 2, "&")
C0_INSTR(or_u8,    u8,   u8,   2, "|")
C0_INSTR(or_u16,   u16,  u16,  2, "|")
C0_INSTR(or_u32,   u32,  u32,  2, "|")
C0_INSTR(or_u64,   u64,  u64,  2, "|")
C0_INSTR(or_u128,  u128, u128, 2, "|")
C0_INSTR(xor_u8,   u8,   u8,   2, "^")
C0_INSTR(xor_u16,  u16,  u16,  2, "^")
C0_INSTR(xor_u32,  u32,  u32,  2, "^")
C0_INSTR(xor_u64,  u64,  u64,  2, "^")
C0_INSTR(xor_u128, u128, u128, 2, "^")
C0_INSTR(eq_u8,     u8,   u8, 2, "==")
C0_INSTR(eq_u16,    u16,  u8, 2, "==")
C0_INSTR(eq_u32,    u32,  u8, 2, "==")
C0_INSTR(eq_u64,    u64,  u8, 2, "==")
C0_INSTR(eq_u128,   u128, u8, 2, "==")
C0_INSTR(neq_u8,    u8,   u8, 2, "!=")
C0_INSTR(neq_u16,   u16,  u8, 2, "!=")
C0_INSTR(neq_u32,   u32,  u8, 2, "!=")
C0_INSTR(neq_u64,   u64,  u8, 2, "!=")
C0_INSTR(neq_u128,  u128, u8, 2, "!=")
C0_INSTR(lt_i8,     i8,   u8, 2, "<")
C0_INSTR(lt_u8,     u8,   u8, 2, "<")
C0_INSTR(lt_i16,    i16,  u8, 2, "<")
C0_INSTR(lt_u16,    u16,  u8, 2, "<")
C0_INSTR(lt_i32,    i32,  u8, 2, "<")
C0_INSTR(lt_u32,    u32,  u8, 2, "<")
C0_INSTR(lt_i64,    i64,  u8, 2, "<")
C0_INSTR(lt_u64,    u64,  u8, 2, "<")
C0_INSTR(lt_i128,   i128, u8, 2, "<")
C0_INSTR(lt_u128,   u128, u8, 2, "<")
C0_INSTR(gt_i8,     i8,   u8, 2, ">")
C0_INSTR(gt_u8,     u8,   u8, 2, ">")
C0_INSTR(gt_i16,    i16,  u8, 2, ">")
C0_INSTR(gt_u16,    u16,  u8, 2, ">")
C0_INSTR(gt_i32,    i32,  u8, 2, ">")
C0_INSTR(gt_u32,    u32,  u8, 2, ">")
C0_INSTR(gt_i64,    i64,  u8, 2, ">")
C0_INSTR(gt_u64,    u64,  u8, 2, ">")
C0_INSTR(gt_i128,   i128, u8, 2, ">")
C0_INSTR(gt_u128,   u128, u8, 2, ">")
C0_INSTR(lteq_i8,   i8,   u8, 2, "<=")
C0_INSTR(lteq_u8,   u8,   u8, 2, "<=")
C0_INSTR(lteq_i16,  i16,  u8, 2, "<=")
C0_INSTR(lteq_u16,  u16,  u8, 2, "<=")
C0_INSTR(lteq_i32,  i32,  u8, 2, "<=")
C0_INSTR(lteq_u32,  u32,  u8, 2, "<=")
C0_INSTR(lteq_i64,  i64,  u8, 2, "<=")
C0_INSTR(lteq_u64,  u64,  u8, 2, "<=")
C0_INSTR(lteq_i128, i128, u8, 2, "<=")
C0_INSTR(lteq_u128, u128, u8, 2, "<=")
C0_INSTR(gteq_i8,   i8,   u8, 2, ">=")
C0_INSTR(gteq_u8,   u8,   u8, 2, ">=")
C0_INSTR(gteq_i16,  i16,  u8, 2, ">=")
C0_INSTR(gteq_u16,  u16,  u8, 2, ">=")
C0_INSTR(gteq_i32,  i32,  u8, 2, ">=")
C0_INSTR(gteq_u32,  u32,  u8, 2, ">=")
C0_INSTR(gteq_i64,  i64,  u8, 2, ">=")
C0_INSTR(gteq_u64,  u64,  u8, 2, ">=")
C0_INSTR(gteq_i128, i128, u8, 2, ">=")
C0_INSTR(gteq_u128, u128, u8, 2, ">=")


C0_INSTR(addf_f16,  f16, f16, 2, "+")
C0_INSTR(addf_f32,  f32, f32, 2, "+")
C0_INSTR(addf_f64,  f64, f64, 2, "+")
C0_INSTR(subf_f16,  f16, f16, 2, "-")
C0_INSTR(subf_f32,  f32, f32, 2, "-")
C0_INSTR(subf_f64,  f64, f64, 2, "-")
C0_INSTR(mulf_f16,  f16, f16, 2, "*")
C0_INSTR(mulf_f32,  f32, f32, 2, "*")
C0_INSTR(mulf_f64,  f64, f64, 2, "*")
C0_INSTR(divf_f16,  f16, f16, 2, "/")
C0_INSTR(divf_f32,  f32, f32, 2, "/")
C0_INSTR(divf_f64,  f64, f64, 2, "/")
C0_INSTR(eqf_f16,   f16, u8, 2, "==")
C0_INSTR(eqf_f32,   f32, u8, 2, "==")
C0_INSTR(eqf_f64,   f64, u8, 2, "==")
C0_INSTR(neqf_f16,  f16, u8, 2, "!=")
C0_INSTR(neqf_f32,  f32, u8, 2, "!=")
C0_INSTR(neqf_f64,  f64, u8, 2, "!=")
C0_INSTR(ltf_f16,   f16, u8, 2, "<")
C0_INSTR(ltf_f32,   f32, u8, 2, "<")
C0_INSTR(ltf_f64,   f64, u8, 2, "<")
C0_INSTR(gtf_f16,   f16, u8, 2, ">")
C0_INSTR(gtf_f32,   f32, u8, 2, ">")
C0_INSTR(gtf_f64,   f64, u8, 2, ">")
C0_INSTR(lteqf_f16, f16, u8, 2, "<=")
C0_INSTR(lteqf_f32, f32, u8, 2, "<=")
C0_INSTR(lteqf_f64, f64, u8, 2, "<=")
C0_INSTR(gteqf_f16, f16, u8, 2, ">=")
C0_INSTR(gteqf_f32, f32, u8, 2, ">=")
C0_INSTR(gteqf_f64, f64, u8, 2, ">=")

C0_INSTR(convert,     void, void, 1, "")
C0_INSTR(reinterpret, void, void, 1, "")

C0_INSTR(atomic_thread_fence, void, void, 0, "")
C0_INSTR(atomic_signal_fence, void, void, 0, "")

C0_INSTR(atomic_load_u8,    ptr,  u8,   1, "")
C0_INSTR(atomic_load_u16,   ptr, u16,  1, "")
C0_INSTR(atomic_load_u32,   ptr, u32,  1, "")
C0_INSTR(atomic_load_u64,   ptr, u64,  1, "")
C0_INSTR(atomic_load_ptr,   ptr, ptr,  1, "")
C0_INSTR(atomic_store_u8,   u8,  void,   2, "")
C0_INSTR(atomic_store_u16,  u16, void,  2, "")
C0_INSTR(atomic_store_u32,  u32, void,  2, "")
C0_INSTR(atomic_store_u64,  u64, void,  2, "")
C0_INSTR(atomic_store_ptr,  ptr, void,  2, "")

C0_INSTR(atomic_xchg_u8,   u8, u8, 2, "")
C0_INSTR(atomic_xchg_u16,  u8, u8, 2, "")
C0_INSTR(atomic_xchg_u32,  u8, u8, 2, "")
C0_INSTR(atomic_xchg_u64,  u8, u8, 2, "")
C0_INSTR(atomic_cas_u8,    u8,  void, 3, "")
C0_INSTR(atomic_cas_u16,   u16, void, 3, "")
C0_INSTR(atomic_cas_u32,   u32, void, 3, "")
C0_INSTR(atomic_cas_u64,   u64, void, 3, "")

C0_INSTR(atomic_add_u8,   u8,  u8,   2, "")
C0_INSTR(atomic_add_u16,  u16, u16,  2, "")
C0_INSTR(atomic_add_u32,  u32, u32,  2, "")
C0_INSTR(atomic_add_u64,  u64, u64,  2, "")
C0_INSTR(atomic_sub_u8,   u8,  u8,   2, "")
C0_INSTR(atomic_sub_u16,  u16, u16,  2, "")
C0_INSTR(atomic_sub_u32,  u32, u32,  2, "")
C0_INSTR(atomic_sub_u64,  u64, u64,  2, "")
C0_INSTR(atomic_and_u8,   u8,  u8,   2, "")
C0_INSTR(atomic_and_u16,  u16, u16,  2, "")
C0_INSTR(atomic_and_u32,  u32, u32,  2, "")
C0_INSTR(atomic_and_u64,  u64, u64,  2, "")
C0_INSTR(atomic_or_u8,    u8,  u8,   2, "")
C0_INSTR(atomic_or_u16,   u16, u16,  2, "")
C0_INSTR(atomic_or_u32,   u32, u32,  2, "")
C0_INSTR(atomic_or_u64,   u64, u64,  2, "")
C0_INSTR(atomic_xor_u8,   u8,  u8,   2, "")
C0_INSTR(atomic_xor_u16,  u16, u16,  2, "")
C0_INSTR(atomic_xor_u32,  u32, u32,  2, "")
C0_INSTR(atomic_xor_u64,  u64, u64,  2, "")

C0_INSTR(select_u8,   u8,   u8,   3, "")
C0_INSTR(select_u16,  u16,  u16,  3, "")
C0_INSTR(select_u32,  u32,  u32,  3, "")
C0_INSTR(select_u64,  u64,  u64,  3, "")
C0_INSTR(select_u128, u128, u128, 3, "")
C0_INSTR(select_f16,  f16,  f16,  3, "")
C0_INSTR(select_f32,  f32,  f32,  3, "")
C0_INSTR(select_f64,  f64,  f64,  3, "")
C0_INSTR(select_ptr,  ptr,  ptr,  3, "")

C0_INSTR(memmove, ptr, void, 3, "")
C0_INSTR(memset,  ptr, void, 3, "")

C0_INSTR(decl, void, void, 0, "")
C0_INSTR(addr, ptr, ptr, 1, "")
C0_INSTR(index_ptr, ptr, ptr, 2, "")
C0_INSTR(field_ptr, ptr, ptr, 1, "")

C0_INSTR(call,  void, void, -1, "")

C0_INSTR(if,    void, void, -1, "")
C0_INSTR(loop,  void, void, 0,  "")
C0_INSTR(block, void, void, 0,  "")

C0_INSTR(continue,    void, void, 0,  "")
C0_INSTR(break,       void, void, 0,  "")
C0_INSTR(return,      void, void, -1, "")
C0_INSTR(unreachable, void, void, 0,  "")
C0_INSTR(goto,        void, void, 1,  "")
C0_INSTR(label,       void, void, 0,  "")

#undef C0_INSTR