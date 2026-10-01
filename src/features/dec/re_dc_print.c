// re_dc_print.c - turning varnodes and ops into text.
// Module: feature (C11).
// Owns: the name tables, the value renderer, and the one statement writer.
// Depends: re_dc_print.h. No x86 detail: a register is named by the backend.
// Depends: re_dc_print.h. No x86 detail appears here: a register is named by the
//       backend through the vtable, and nothing else knows what an instruction is.
#include "features/dec/re_dc_print.h"

#include "features/meta/re_disasm.h"

#include <stdio.h>
#include <string.h>

// in one statement cannot collide.
const char *re_dc_local(re_dc_emit_t *e, int16_t disp) {
    unsigned m = disp < 0 ? (unsigned)(-(int)disp) : (unsigned)disp;
    snprintf(e->lname, (size_t)RE_DC_TEXT, "%s%u", disp < 0 ? "local_m" : "local_p", m);
    return e->lname;
}

// A value the emitter can print: a name we minted, a register that was read before
// it was written, or a literal. Keeping it as text is what lets the same code path
// print an operand, a right hand side and a comparison operand without caring which
// of the three it is.
const char *re_dc_val(re_dc_emit_t *e, re_varnode_t vn, char *scratch) {
    if (vn.space == RE_SPACE_CONST) {
        // A constant's value lives in the op that defined it, keyed by this id, so a
        // 64 bit value survives a 16 bit offset field and two constants never mix. An
        // address is printed in hex, because that is how every other part of the tool
        // prints one and how a reader will compare it against a disassembly.
        if (vn.offset < RE_DC_VARS) {
            if (e->caddr[vn.offset])
                snprintf(scratch, RE_DC_TEXT, "0x%llx", (unsigned long long)e->cval[vn.offset]);
            else
                snprintf(scratch, RE_DC_TEXT, "%lld", (long long)e->cval[vn.offset]);
            return scratch;
        }
        snprintf(scratch, RE_DC_TEXT, "?");
        return scratch;
    }
    if (vn.space == RE_SPACE_UNIQUE)
        return (vn.offset < RE_DC_VARS && e->uniq[vn.offset].p) ? (const char *)e->uniq[vn.offset].p
                                                                : "cond";
    if (vn.space == RE_SPACE_STACK) {
        snprintf(scratch, RE_DC_TEXT, "&%s", re_dc_local(e, (int16_t)vn.offset));
        return scratch;
    }
    if (vn.space == RE_SPACE_REG && vn.offset < RE_DC_REGS && e->reg[vn.offset].p)
        return (const char *)e->reg[vn.offset].p;
    // A register read before it was written, or one the emitter never bound. The
    // backend names it, so the output still says rax rather than r0.
    if (e->dis && e->dis->reg_name) {
        const char *n = e->dis->reg_name(e->dis->ctx, vn.offset);
        if (n)
            return n;
    }
    snprintf(scratch, RE_DC_TEXT, "r%u", vn.offset);
    return scratch;
}

re_str_t re_dc_mint(re_dc_emit_t *e, const char *prefix, uint32_t n) {
    char buf[24];
    int k = snprintf(buf, sizeof(buf), "%s%u", prefix, n);
    re_str_t s;
    s.p = (const char *)re_arena_memdup(e->a, buf, (size_t)k);
    s.n = (uint32_t)k;
    return s;
}

void re_dc_bind(re_dc_emit_t *e, re_varnode_t vn, re_str_t name) {
    if (vn.space == RE_SPACE_REG && vn.offset < RE_DC_REGS) {
        e->reg[vn.offset] = name;
        e->touched[vn.offset] = true;
    }
    // A temporary is named once, where it is defined, and every later reference to
    // it prints that same name. Without this the backend's load, operate, store for
    // a memory destination would print three unrelated names.
    if (vn.space == RE_SPACE_UNIQUE && vn.offset < RE_DC_VARS)
        e->uniq[vn.offset] = name;
}

void re_dc_fmt(char *dst, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
}

void re_dc_stmt(re_dc_emit_t *e, const char *fmt, ...) {
    va_list ap;
    if (e->n_stmts && e->n_stmts % 6 == 0)
        re_strbuf_puts(e->o, "\n");
    re_strbuf_puts(e->o, "    ");
    va_start(ap, fmt);
    {
        char buf[160];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        re_strbuf_puts(e->o, buf);
    }
    va_end(ap);
    re_strbuf_puts(e->o, ";\n");
    e->n_stmts++;
}

// The C spelling of a binary arithmetic op, or NULL when the op has no C form here
// and must be printed some other way. Grouped so the table and the emitter agree.
const char *re_dc_binop(re_op_kind_t k) {
    switch (k) {
        case RE_OP_INTADD:
            return "+";
        case RE_OP_INTSUB:
            return "-";
        case RE_OP_INTMUL:
            return "*";
        case RE_OP_INTDIV:
            return "/";
        case RE_OP_INTMOD:
            return "%";
        case RE_OP_INTAND:
            return "&";
        case RE_OP_INTOR:
            return "|";
        case RE_OP_INTXOR:
            return "^";
        case RE_OP_INTSHL:
            return "<<";
        case RE_OP_INTSHR:
            return ">>";
        default:
            return NULL;
    }
}

const char *re_dc_ccop(unsigned cc) {
    switch (cc) {
        case RE_CC_OP_EQ:
            return "==";
        case RE_CC_OP_NE:
            return "!=";
        case RE_CC_OP_SLT:
            return "<";
        case RE_CC_OP_SLE:
            return "<=";
        case RE_CC_OP_ULT:
            return "<";
        case RE_CC_OP_ULE:
            return "<=";
        case RE_CC_OP_SGT:
            return ">";
        case RE_CC_OP_SGE:
            return ">=";
        case RE_CC_OP_UGT:
            return ">";
        default:
            return ">=";
    }
}

// The size a load or store touches, printed so the reader can see how wide an access
// it is. A dereference without a width is a bug in the reader's code, not ours.
const char *re_dc_type(uint16_t size) {
    switch (size) {
        case 1:
            return "uint8_t";
        case 2:
            return "uint16_t";
        case 4:
            return "uint32_t";
        default:
            return "uint64_t";
    }
}

// A call target is printed by name when the xref index has one, because the name is
// the reason anyone reads the output. A target with no name is printed as an address,
// which is honest. The arguments are the registers written since the previous call,
// which is the defensible reading of what was passed: the callee's own parameter
// registers say nothing about an arbitrary call's arguments, and printing those would
// be a plausible looking wrong answer. rax is excluded because the previous call
// One op becomes one statement. The op is already lowered, so this is purely a
// question of which C shape fits, and the answer is driven by the op kind rather
// than by the instruction, which is why no x86 detail appears in this function.
