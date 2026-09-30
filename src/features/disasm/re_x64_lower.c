// re_x64_lower.c - lowers a projected x86-64 instruction into the register IR.
// Module: feature (C11).
// Owns: the control flow transfer functions, which are the ones the CFG work needs.
// Depends: re_x64_priv.h. Only control flow is modelled. A data flow instruction
// emits nothing, which the seam defines as not modelled rather than as an error:
// a wrong LOAD is worse than no LOAD, and the data ops arrive with the emitter
// in task 4, where there is a consumer to test them against.
#include "features/disasm/re_x64_priv.h"

// A placeholder for a value the IR has not computed yet. The condition of a
// conditional branch is one of these until the comparison that produced it is
// modelled, and a unique space temp is exactly what it means.
static re_varnode_t pending_vn(void) {
    return re_ir_vn(RE_SPACE_UNIQUE, 8, 0);
}

static bool push(re_ir_func_t *f, re_arena_t *a, re_op_kind_t kind, int64_t cval,
                 re_varnode_t in0) {
    re_ir_op_t op = re_ir_mkop((re_ir_op_t){0});
    op.op = kind;
    op.const_val = cval;
    op.in[0] = in0;
    op.out = pending_vn();
    return re_ir_emit(f, a, op) != NULL;
}

// Branches, calls and returns. A direct transfer carries its resolved target as
// the op's constant, and an indirect one carries nothing, because an indirect
// target is not knowable from the instruction and inventing a value here would be
// a confident lie.
static size_t lower_flow(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    int64_t t = (int64_t)in->target;
    re_varnode_t none = pending_vn();
    if (in->is_return)
        return push(f, a, RE_OP_RETURN, 0, none) ? 1u : 0u;
    if (in->is_call) {
        re_op_kind_t k = in->has_target ? RE_OP_CALL : RE_OP_CALLIND;
        return push(f, a, k, in->has_target ? t : 0, none) ? 1u : 0u;
    }
    if (!in->is_branch)
        return 0;
    if (in->is_conditional)
        return push(f, a, RE_OP_CBRANCH, in->has_target ? t : 0, none) ? 1u : 0u;
    return push(f, a, RE_OP_BRANCH, in->has_target ? t : 0, none) ? 1u : 0u;
}

size_t x64_lower(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    return lower_flow(in, f, a);
}
