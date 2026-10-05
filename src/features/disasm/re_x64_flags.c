// re_x64_flags.c - the flag model every x86-64 lowering shares.
// Module: feature (C11).
// Owns: flag varnodes and the hidden comparison a flag writer records.
// Depends: re_x64_priv.h and re_ir. The x86 condition names live in re_ir.h.
#include "features/disasm/re_x64_priv.h"

#include "features/dec/re_ir.h"

re_varnode_t x64_flag_vn(unsigned flag) {
    return re_ir_vn(RE_SPACE_FLAG, 1, (uint16_t)(flag & 7u));
}

// The comparison a flag writer records. It prints nothing and defines nothing:
// the emitter keeps it as pending state and lets the next conditional branch
// turn it into the condition the architecture actually tested. Which operands
// are recorded depends on the writer: a comparison or a test records its two
// operands, and every other writer records its result against zero.
bool x64_flags_pair(re_ir_func_t *f, re_arena_t *a, unsigned kind, re_varnode_t a0,
                    re_varnode_t b0) {
    re_ir_op_t o = re_ir_mkop((re_ir_op_t){0});
    o.op = RE_OP_CMP;
    o.in[0] = a0;
    o.in[1] = b0;
    o.extra = kind;
    return re_ir_emit(f, a, o) != NULL;
}

// The result form. The zero is minted the way every other constant is, so the
// emitter's folding sees one shape no matter which lowering wrote the flags.
bool x64_flags_result(re_ir_func_t *f, re_arena_t *a, unsigned kind, re_varnode_t result) {
    re_ir_op_t o = re_ir_mkop((re_ir_op_t){0});
    re_varnode_t zero = re_ir_vn(RE_SPACE_CONST, 8, (uint16_t)f->next_uniq);
    o.op = RE_OP_CONST;
    o.out = zero;
    o.const_val = 0;
    o.extra = RE_CONST_OPERAND;
    if (re_ir_emit(f, a, o) == NULL)
        return false;
    f->next_uniq++;
    return x64_flags_pair(f, a, kind, result, zero);
}
