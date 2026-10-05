// re_x64_lower_simd.c - the vector and scalar float tranche of the lowering.
// Module: feature (C11).
// Owns: the 0F map's data movement, float arithmetic, conversions and compares.
// Depends: re_x64_priv.h. Vector registers arrived projected onto their base,
//           so a mixed form rebuilds its general purpose operand from the raw
//           ModRM fields the projection also carries.
#include "features/disasm/re_x64_priv.h"

#include "features/dec/re_ir.h"

// The opcode ranges of the 0F map whose operands are vector registers, read
// back off the projected record. This is the same test the projection used,
// which is the point: a form the projection called vector is one this file
// lowers, and nothing else gets past the gate.
static bool is_simd_op(const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    if (RE_INSN_MAP(in) != 1)
        return false;
    if (op == 0xC3u || op == 0x0Fu)
        return false; // movnti moves a general purpose register; 0F is 3DNow
    return (op >= 0x10u && op <= 0x17u) || (op >= 0x28u && op <= 0x2Fu) ||
           (op >= 0x50u && op <= 0x7Fu) || (op >= 0xC2u && op <= 0xC6u) ||
           (op >= 0xD0u && op <= 0xFEu);
}

// The width a scalar float form moves: four or eight bytes, by the prefix.
static uint16_t scalar_w(const re_insn_t *in) {
    return in->pfx == 2 ? 4u : in->pfx == 3 ? 8u : 16u;
}

// The packed width: sixteen bytes, or thirty two under a VEX length bit.
static uint16_t packed_w(const re_insn_t *in) {
    return in->vex_l ? 32u : 16u;
}

static bool vload(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t w,
                  re_varnode_t dst) {
    re_varnode_t addr;
    re_ir_op_t o;
    (void)w; // the width lives in the destination varnode the caller chose
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o = x64_lower_mk(RE_OP_LOAD);
    o.out = dst;
    o.in[0] = addr;
    return x64_lower_push(f, a, o);
}

static bool vstore(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t w,
                   re_varnode_t src) {
    re_varnode_t addr;
    re_ir_op_t o;
    if (!x64_lower_addr(f, a, in, &addr))
        return false;
    o = x64_lower_mk(RE_OP_STORE);
    o.in[0] = re_ir_vn(RE_SPACE_HEAP, w, 0);
    o.in[1] = src;
    o.in[2] = addr;
    return x64_lower_push(f, a, o);
}

// The value of the r/m side at the width this form moves: a register varnode,
// or a freshly minted temporary the caller loads into.
static bool rm_value(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t w, bool gp,
                     re_varnode_t *out) {
    if (!in->is_mem) {
        *out = gp ? re_ir_vn(RE_SPACE_REG, w, (in->ops[3] & 7u) + ((in->rex & 1u) ? 8u : 0u))
                  : re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->rm);
        return true;
    }
    *out = x64_lower_uniq(f, w);
    return vload(f, a, in, w, *out);
}

// The register to register and register to memory moves: movups, movaps and
// their scalar and double forms, plus the high and low half moves, which all
// read as one load, one store or one copy at the width the form moves.
static bool lower_vmov(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t w) {
    unsigned op = RE_INSN_OPCODE(in);
    bool into_reg = op == 0x10u || op == 0x28u || op == 0x12u || op == 0x16u;
    re_varnode_t xv = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->reg);
    re_ir_op_t o;
    if (into_reg) {
        if (!in->is_mem) {
            o = x64_lower_mk(RE_OP_VAR);
            o.out = xv;
            o.in[0] = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->rm);
            return x64_lower_push(f, a, o);
        }
        return vload(f, a, in, w, xv);
    }
    if (!in->is_mem) {
        o = x64_lower_mk(RE_OP_VAR);
        o.out = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->rm);
        o.in[0] = xv;
        return x64_lower_push(f, a, o);
    }
    return vstore(f, a, in, w, xv);
}

// movd and movq between the vector file and the general purpose one, in both
// directions, at four bytes or at eight under REX.W or VEX.W. The vector side
// keeps its full width in the cast's output, which is how a reader sees that
// only the low half moved.
static bool lower_vmix(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, bool into_vec) {
    uint16_t w = (in->rex & 8u) || in->vex_w ? 8u : 4u;
    re_varnode_t xv = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->reg);
    re_varnode_t g;
    re_ir_op_t o;
    if (into_vec) {
        if (!rm_value(f, a, in, w, true, &g))
            return false;
        o = x64_lower_mk(RE_OP_FCAST);
        o.out = xv;
        o.in[0] = g;
        return x64_lower_push(f, a, o);
    }
    if (!rm_value(f, a, in, w, true, &g))
        return false;
    o = x64_lower_mk(RE_OP_FCAST);
    o.out = g;
    o.in[0] = xv;
    return x64_lower_push(f, a, o);
}

// movq between vector registers and memory, and the packed integer moves 6F
// and 7F at their own width.
static bool lower_vmovq(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in, uint16_t w) {
    unsigned op = RE_INSN_OPCODE(in);
    bool into_reg = op == 0x6Fu;
    re_varnode_t xv = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->reg);
    re_ir_op_t o;
    if (into_reg)
        return in->is_mem
                   ? vload(f, a, in, w, xv)
                   : x64_ld_form2(f, a, RE_OP_VAR, xv, re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->rm),
                                  re_ir_vn(RE_SPACE_UNIQUE, 0, 0), &xv);
    if (in->is_mem)
        return vstore(f, a, in, w, xv);
    o = x64_lower_mk(RE_OP_VAR);
    o.out = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->rm);
    o.in[0] = xv;
    return x64_lower_push(f, a, o);
}

// The packed and scalar float arithmetic: add, mul, sub and div, at whatever
// width the prefix states. A memory operand loads first at exactly that width.
static bool lower_varith(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    uint16_t w = in->pfx >= 2 ? scalar_w(in) : packed_w(in);
    re_op_kind_t kind = op == 0x58u   ? RE_OP_FADD
                        : op == 0x59u ? RE_OP_FMUL
                        : op == 0x5Cu ? RE_OP_FSUB
                                      : RE_OP_FDIV;
    re_varnode_t src = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->reg);
    re_varnode_t val;
    if (!rm_value(f, a, in, w, false, &val))
        return false;
    return x64_ld_form2(f, a, kind, src, src, val, &src);
}

// The conversion forms: 2A into the vector file, 2C and 2D out of it, 5A
// between the widths. All of them are one cast, which is what the emitter
// prints and what a reader expects from a conversion.
static bool lower_vcvt(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    unsigned op = RE_INSN_OPCODE(in);
    uint16_t sw = scalar_w(in);
    re_varnode_t val;
    re_ir_op_t o;
    if (op == 0x2Au) {
        uint16_t gw = (in->rex & 8u) || in->vex_w ? 8u : 4u;
        if (!rm_value(f, a, in, gw, true, &val))
            return false;
        o = x64_lower_mk(RE_OP_FCAST);
        o.out = re_ir_vn(RE_SPACE_REG, sw, (uint16_t)in->reg);
        o.in[0] = val;
        return x64_lower_push(f, a, o);
    }
    if (op == 0x5Au) {
        if (!rm_value(f, a, in, sw, false, &val))
            return false;
        o = x64_lower_mk(RE_OP_FCAST);
        o.out = re_ir_vn(RE_SPACE_REG, sw == 4 ? 8u : 4u, (uint16_t)in->reg);
        o.in[0] = val;
        return x64_lower_push(f, a, o);
    }
    if (!rm_value(f, a, in, sw, false, &val))
        return false;
    o = x64_lower_mk(RE_OP_FCAST);
    o.out = re_ir_vn(RE_SPACE_REG, 4, (in->ops[3] & 7u) + ((in->rex & 1u) ? 8u : 0u));
    o.in[0] = val;
    return x64_lower_push(f, a, o);
}

// ucomis and comis set the flags a conditional branch reads. The recorded pair
// is the comparison itself, so a branch after one prints as the float compare
// it tested, with the unordered cases falling to the honest flag names.
static bool lower_vcmp(re_ir_func_t *f, re_arena_t *a, const re_insn_t *in) {
    uint16_t w = scalar_w(in);
    re_varnode_t src = re_ir_vn(RE_SPACE_REG, w, (uint16_t)in->reg);
    re_varnode_t val;
    if (!rm_value(f, a, in, w, false, &val))
        return false;
    return x64_flags_pair(f, a, RE_SETF_CMP, src, val);
}

bool x64_lower_simd(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a) {
    unsigned op;
    if (!is_simd_op(in) || !x64_lower_uniq_ok(f))
        return false;
    op = RE_INSN_OPCODE(in);
    if (op == 0x10u || op == 0x11u || op == 0x28u || op == 0x29u || op == 0x12u || op == 0x13u ||
        op == 0x16u || op == 0x17u)
        return lower_vmov(f, a, in, in->pfx >= 2 ? scalar_w(in) : packed_w(in));
    if (op == 0x6Eu)
        return lower_vmix(f, a, in, true);
    if (op == 0x7Eu)
        return lower_vmix(f, a, in, false);
    if (op == 0x6Fu || op == 0x7Fu || op == 0xD6u)
        return lower_vmovq(f, a, in, in->pfx == 0 ? 8u : packed_w(in));
    if (op == 0x58u || op == 0x59u || op == 0x5Cu || op == 0x5Eu)
        return lower_varith(f, a, in);
    if (op == 0x2Au || op == 0x2Cu || op == 0x2Du || op == 0x5Au)
        return lower_vcvt(f, a, in);
    if (op == 0x2Eu || op == 0x2Fu)
        return lower_vcmp(f, a, in);
    return false;
}
