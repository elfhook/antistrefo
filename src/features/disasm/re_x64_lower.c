// re_x64_lower.c - lowers a projected x86-64 instruction into the register IR.
// Module: feature (C11).
// Owns: the transfer functions for the integer subset, and nothing else.
// Depends: re_x64_priv.h. The lowering is deliberately stateless with respect to
//           control flow: it reads one instruction and emits ops for it. Constant
//           folding and register tracking belong to the emitter, which already has
//           to model control flow, and a backend that remembered cross instruction
//           state would have to be reset per function. The one counter it does keep
//           lives in the IR, which is itself per function.
#include "features/disasm/re_x64_priv.h"

#include "features/re_ir.h"

// The operation size in bytes. Most forms follow the operand size prefix, but a few
// have their own width and get it wrong if the prefix is consulted instead. Only 0x82
// is byte sized among the immediate group: 0x80, 0x81 and 0x83 all honour the prefix,
// and treating them as byte operations would misread every stack adjustment.
static uint16_t osize_of(const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    unsigned map = RE_INSN_MAP(in);
    if (map == 1 && (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF))
        return 1;
    if (map == 0 && (op == 0x88 || op == 0x8A || op == 0xC6 || (op >= 0xB0 && op <= 0xB7) ||
                     (op >= 0x70 && op <= 0x7F) || op == 0x82))
        return 1;
    return (uint16_t)in->opsize;
}

static re_varnode_t reg_vn(const re_insn_t *in, unsigned r) {
    return re_ir_vn(RE_SPACE_REG, osize_of(in), (uint16_t)r);
}

// A constant varnode. The value is not in the varnode, it is in the op that defines
// it, which is what lets a 64 bit immediate travel through a 16 bit offset field.
// The offset is a unique id, because two constants in the same function must be told
// apart by whatever consumes them: an address and an immediate both print through
// this path, and folding the wrong one would be a silent wrong answer.
static re_varnode_t const_vn(re_ir_func_t *f) {
    return re_ir_vn(RE_SPACE_CONST, 8, (uint16_t)f->next_uniq++);
}

static re_varnode_t uniq_vn(re_ir_func_t *f, uint16_t size) {
    return re_ir_vn(RE_SPACE_UNIQUE, size, (uint16_t)f->next_uniq++);
}

// A fresh temporary, or false when the function has run out. The bound matters: the
// emitter names temporaries through a fixed table, so a function that minted more
// than the table holds could not be printed correctly. Refusing is better than
// printing a name that refers to the wrong value.
static bool uniq_ok(const re_ir_func_t *f) {
    return f->next_uniq < RE_UNIQ_MAX;
}

// The memory operand as an address. A frame relative access becomes a STACK varnode
// so the emitter can name it as a local; anything else is a HEAP address, which is
// the honest description when the base is a register whose value we do not know.
static re_varnode_t mem_vn(const re_insn_t *in) {
    if (in->base == 4 || in->base == 5) // rsp or rbp
        return re_ir_vn(RE_SPACE_STACK, 8, (uint16_t)(int16_t)in->disp);
    return re_ir_vn(RE_SPACE_HEAP, 8, 0);
}

static re_ir_op_t mk(re_op_kind_t kind) {
    re_ir_op_t op = re_ir_mkop((re_ir_op_t){0});
    op.op = kind;
    return op;
}

static bool push(re_ir_func_t *f, re_arena_t *a, re_ir_op_t op) {
    return re_ir_emit(f, a, op) != NULL;
}

// The r/m operand as a value. A register is its own name; a memory operand is a
// value of unknown provenance until a load brings it in.
static re_varnode_t rm_vn(const re_insn_t *in) {
    if (!in->is_mem)
        return reg_vn(in, in->rm);
    return re_ir_vn(RE_SPACE_HEAP, osize_of(in), 0);
}

// Emit the address of the memory operand and hand back the varnode that names it, so
// the caller references the address it just produced rather than re-deriving one. A
// RIP relative address is a constant, which is the only case where the value is
// known; the other forms name the frame slot or stay abstract.
static bool push_addr(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_varnode_t *out) {
    re_ir_op_t op = in->rip_rel ? mk(RE_OP_CONST) : mk(RE_OP_VAR);
    op.out = in->rip_rel ? const_vn(f) : mem_vn(in);
    op.const_val = in->rip_rel ? (int64_t)in->mem : 0;
    // An address exists only to be an operand of the load or store that follows, so
    // the emitter is told not to print it as a statement of its own.
    if (in->rip_rel)
        op.extra = RE_CONST_OPERAND;
    if (!push(f, a, op))
        return false;
    *out = op.out;
    return true;
}

// An immediate operand, emitted as its own CONST so the value is in the IR and not
// only in a field the emitter would have to know to look in. This is what the
// emitter's constant folding resolves, the same way it resolves an address.
static bool push_imm(re_ir_func_t *f, re_arena_t *a, int64_t v, re_varnode_t *out) {
    re_ir_op_t op = mk(RE_OP_CONST);
    op.out = const_vn(f);
    op.const_val = v;
    op.extra = RE_CONST_OPERAND;
    if (!push(f, a, op))
        return false;
    *out = op.out;
    return true;
}

// The three mov forms that carry an immediate. Separated from the register forms
// because they are the only ones that need a second varnode, and mixing the two is
// what made this function too long to read.
static bool lower_mov_imm(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    re_ir_op_t o;
    re_varnode_t addr = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    if (op >= 0xB0 && op <= 0xBF) { // mov reg8, imm8
        o = mk(RE_OP_CONST);
        o.out = reg_vn(in, (op - 0xB0u) + ((in->rex & 1u) ? 8u : 0u));
        o.const_val = in->imm;
        return push(f, a, o);
    }
    if (!in->is_mem) { // mov reg, imm
        o = mk(RE_OP_CONST);
        o.out = rm_vn(in);
        o.const_val = in->imm;
        return push(f, a, o);
    }
    // A store of a constant: the address, then the value, then the store. The two live
    // in separate varnodes because the emitter folds the constant it last saw, and
    // overwriting the address with the value would lose the store target.
    re_varnode_t imm;
    if (!push_addr(f, a, in, &addr) || !push_imm(f, a, in->imm, &imm))
        return false;
    o = mk(RE_OP_STORE);
    o.in[0] = rm_vn(in);
    o.in[1] = imm;
    o.in[2] = addr;
    return push(f, a, o);
}

static bool lower_mov(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    re_ir_op_t o;
    re_varnode_t addr = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    if (op == 0xC6 || op == 0xC7 || (op >= 0xB0 && op <= 0xBF))
        return lower_mov_imm(f, a, in);
    if (op == 0x88 || op == 0x89) { // mov r/m, reg
        bool mem = in->is_mem;
        if (mem && !push_addr(f, a, in, &addr))
            return false;
        o = mk(RE_OP_STORE);
        o.in[0] = rm_vn(in);
        o.in[1] = reg_vn(in, in->reg);
        o.in[2] = mem ? addr : o.in[0];
        return push(f, a, o);
    }
    if (op == 0x8A || op == 0x8B) { // mov reg, r/m
        o = mk(in->is_mem ? RE_OP_LOAD : RE_OP_VAR);
        o.out = reg_vn(in, in->reg);
        if (in->is_mem) {
            if (!push_addr(f, a, in, &addr))
                return false;
            o.in[0] = addr;
        } else {
            o.in[0] = reg_vn(in, in->rm);
        }
        return push(f, a, o);
    }
    if (op == 0x8D) { // lea reg, mem
        // The result is the address, not what is stored there, so the address op is
        // the substance of the instruction and the register is a copy of it.
        re_varnode_t src;
        if (!push_addr(f, a, in, &src))
            return false;
        o = mk(RE_OP_VAR);
        o.out = reg_vn(in, in->reg);
        o.in[0] = src;
        return push(f, a, o);
    }
    return false;
}

// The operation an arithmetic opcode performs. The 0x00..0x3D block is eight
// operations in runs of eight, so the operation is the top three bits of the opcode
// and the low five only choose the form. The two carry operations are left
// unmodelled: dropping the carry would be wrong, and modelling it would need flag
// state this IR does not carry.
static re_op_kind_t arith_kind(unsigned op) {
    static const re_op_kind_t kOps[8] = {RE_OP_INTADD, RE_OP_INTOR,  RE_OP_UNIMPL, RE_OP_UNIMPL,
                                         RE_OP_INTAND, RE_OP_INTSUB, RE_OP_INTXOR, RE_OP_CMP};
    if (op <= 0x3D)
        return kOps[op >> 3];
    if (op >= 0x80 && op <= 0x83)
        return RE_OP_INTADD; // refined by the reg field
    return RE_OP_UNIMPL;
}

// The immediate group picks its operation from the reg field, so 0x83 is eight
// different instructions. The two with a carry (ADC, SBB) are left unmodelled for the
// same reason as above: the carry is not in this IR.
static re_op_kind_t group_kind(unsigned reg) {
    static const re_op_kind_t k[8] = {RE_OP_INTADD, RE_OP_INTOR,  RE_OP_UNIMPL, RE_OP_UNIMPL,
                                      RE_OP_INTAND, RE_OP_INTSUB, RE_OP_INTXOR, RE_OP_CMP};
    return k[reg & 7u];
}

// A read modify write: a load, then the operation. When the destination is memory
// the result is stored back; when it is a register it is simply left there. Split
// out so lower_alu stays readable, and because the IR has no in place arithmetic.
static bool lower_rmw(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, re_op_kind_t kind,
                      re_varnode_t second, re_varnode_t dest, bool store_back) {
    re_ir_op_t o = mk(RE_OP_LOAD);
    re_ir_op_t result;
    re_varnode_t addr;
    re_varnode_t result_vn;
    if (!push_addr(f, a, in, &addr))
        return false;
    o.out = uniq_vn(f, osize_of(in));
    o.in[0] = addr;
    if (!push(f, a, o))
        return false;
    result = mk(kind);
    // A register destination is written directly; a memory one needs a temporary,
    // because the value has to exist before it can be stored.
    result.out = (dest.space == RE_SPACE_REG) ? dest : uniq_vn(f, osize_of(in));
    result.in[0] = o.out;
    result.in[1] = second;
    if (!push(f, a, result))
        return false;
    result_vn = result.out;
    if (!store_back)
        return true;
    if (!push_addr(f, a, in, &addr))
        return false;
    o = mk(RE_OP_STORE);
    o.in[0] = rm_vn(in);
    o.in[1] = result_vn;
    o.in[2] = addr;
    return push(f, a, o);
}

// test is not cmp: it computes the same flags but has no second operand, because
// both operands are the same value by construction. Lowering it as a comparison
// against that value would print "if (rax == rax)", which is never what the author
// wrote and always vacuously true, so it becomes a comparison against zero instead.
static bool lower_test(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    re_ir_op_t o = mk(RE_OP_CMP);
    re_varnode_t zero;
    if (!push_imm(f, a, 0, &zero))
        return false;
    o.out = uniq_vn(f, 1);
    o.in[0] = rm_vn(in);
    o.in[1] = zero;
    o.extra = RE_CC_OP_EQ;
    return push(f, a, o);
}

// Whether this opcode form carries an immediate. It cannot be inferred from the
// immediate being non zero, because "and qword [rax+0x18], 0" is a real instruction
// whose immediate is zero, and reading that as a register operand would substitute a
// register for a number the author wrote. So the form decides, from the opcode.
static bool alu_has_imm(unsigned op) {
    if (op >= 0x80 && op <= 0x83) // the group form always has an immediate byte
        return true;
    if (op <= 0x3D) // 0x00..0x3D: the low three bits pick the form
        return (op & 7u) == 4u || (op & 7u) == 5u;
    if (op == 0x81 || op == 0xA9 || op == 0xBA || op == 0xC1) // test with immediate
        return true;
    return false;
}

// The accumulator forms 0x04, 0x05 and 0x0C, 0x0D, 0x14, 0x15 and their relatives
// have no ModRM byte, so their operand is rax by definition and the projection leaves
// the register fields unset. Reading the unset field would name a random register.
static bool alu_is_acc(unsigned op) {
    return op <= 0x3D && ((op & 7u) == 4u || (op & 7u) == 5u);
}

// The register destination of a two operand form. The 0x00..0x3B block is laid out
// in fours: the first pair is r/m with a register, the second pair is a register with
// r/m. So bit 1 picks the direction and bit 0 only picks the width.
static bool alu_to_reg(unsigned op) {
    if (op > 0x3D || alu_is_acc(op))
        return false;
    return (op & 2u) != 0u;
}

static bool lower_alu(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    re_op_kind_t kind = arith_kind(op);
    re_ir_op_t o;
    re_varnode_t second = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    re_varnode_t dst;
    bool imm_form = alu_has_imm(op);
    bool acc = alu_is_acc(op);
    bool to_reg = alu_to_reg(op);
    if (op >= 0x80 && op <= 0x83)
        kind = group_kind(in->reg);
    if (kind == RE_OP_UNIMPL || !uniq_ok(f))
        return false;
    if (imm_form && !push_imm(f, a, in->imm, &second))
        return false;
    if (!imm_form)
        second = reg_vn(in, in->reg);
    if (acc) {
        dst = reg_vn(in, 0);
    } else if (in->is_mem) {
        return lower_rmw(f, a, in, kind, second, to_reg ? reg_vn(in, in->reg) : rm_vn(in), !to_reg);
    } else {
        dst = to_reg ? reg_vn(in, in->reg) : rm_vn(in);
    }
    o = mk(kind);
    o.out = dst;
    o.in[0] = dst;
    o.in[1] = second;
    return push(f, a, o);
}

static bool lower_movzx(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    re_ir_op_t o = mk(RE_OP_CAST);
    re_varnode_t addr;
    o.out = reg_vn(in, in->reg);
    if (in->is_mem) {
        if (!push_addr(f, a, in, &addr))
            return false;
        o.in[0] = addr;
    } else {
        o.in[0] = rm_vn(in);
    }
    // const_val carries the source width, which is the one and two byte forms.
    o.const_val = (int64_t)osize_of(in);
    return push(f, a, o);
}

// The condition a conditional branch tests, from the low three bits of its opcode.
// A compare sets the flags and the branch reads them, so the branch's condition is
// the condition of the comparison that preceded it, and the emitter can print the
// two as one expression. The signed and unsigned forms are deliberately kept apart:
// a test against zero is the same either way, but a test against a bound is not, and
// choosing wrongly would be a silent wrong answer.
static unsigned jcc_cond(const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in) & 7u;
    static const unsigned k[8] = {RE_CC_OP_ULE, RE_CC_OP_UGT, RE_CC_OP_ULT, RE_CC_OP_UGE,
                                  RE_CC_OP_EQ,  RE_CC_OP_NE,  RE_CC_OP_ULE, RE_CC_OP_UGT};
    return k[op];
}

// Branches, calls and returns, which are the ops the CFG work needs and the only
// ones here that carry control flow. A direct transfer carries its resolved target
// as the op's constant, and an indirect one carries nothing, because an indirect
// target is not knowable from the instruction.
static bool lower_flow(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    re_ir_op_t o = mk(RE_OP_UNIMPL);
    int64_t t = (int64_t)in->target;
    if (in->is_return) {
        o.op = RE_OP_RETURN;
        // The integer return value is rax. A float return would come back in xmm0,
        // which this emitter does not model, so naming rax is the honest minimum.
        o.out = reg_vn(in, 0);
        o.in[0] = o.out;
        return push(f, a, o);
    }
    if (in->is_call) {
        o.op = in->has_target ? RE_OP_CALL : RE_OP_CALLIND;
        o.out = reg_vn(in, 0);
        o.const_val = t;
        return push(f, a, o);
    }
    if (!in->is_branch)
        return false;
    o.op = in->is_conditional ? RE_OP_CBRANCH : RE_OP_BRANCH;
    o.out = uniq_vn(f, 1);
    o.const_val = t;
    o.extra = in->is_conditional ? jcc_cond(in) : 0u;
    return push(f, a, o);
}

// How many ops the current block already holds, so a caller can tell how many this
// instruction added. The vtable contract is a count, not a yes, and an instruction
// with an immediate or a memory address is worth several ops.
static size_t ops_in(const re_ir_func_t *f) {
    if (!f->n_blocks)
        return 0;
    return f->blocks[f->n_blocks - 1].n_ops;
}

static bool lower_one(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    unsigned map = RE_INSN_MAP(in);
    unsigned op = RE_INSN_OPCODE(in);
    if (lower_flow(in, f, a))
        return true;
    if (map == 1 && (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF))
        return lower_movzx(f, a, in);
    if (map != 0)
        return false;
    if (op == 0x84 || op == 0x85)
        return lower_test(f, a, in);
    if ((op >= 0x88 && op <= 0x8D) || op == 0xC6 || op == 0xC7 || (op >= 0xB0 && op <= 0xBF))
        return lower_mov(f, a, in);
    if (arith_kind(op) != RE_OP_UNIMPL || (op >= 0x80 && op <= 0x83))
        return lower_alu(f, a, in);
    return false;
}

size_t x64_lower(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    size_t before = ops_in(f);
    if (!lower_one(in, f, a))
        return 0;
    return ops_in(f) - before;
}
