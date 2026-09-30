// re_x64_text.c - renders one projected x86-64 instruction as text.
// Module: feature (C11).
// Owns: mnemonic selection for the group opcodes and operand formatting.
// Depends: re_x64_priv.h and the opcode tables. Never reads the image.
#include "features/disasm/re_x64_priv.h"

#include "features/disasm/re_x64_tab.h"
#include "features/disasm/re_x64_tab0f.h"

// The group opcodes pick their mnemonic from the reg field, which is why the
// table only had a placeholder for them.
static const char *const kGrp1[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
static const char *const kGrp2[8] = {"rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"};
static const char *const kGrp3[8] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
static const char *const kGrp4[2] = {"inc", "dec"};
static const char *const kGrp5[6] = {"inc", "dec", "call", "lcall", "jmp", "ljmp"};
static const char *const kGrp8[8] = {"", "", "", "", "bt", "bts", "btr", "btc"};

static const char *pick(const char *const *set, size_t n, unsigned idx) {
    return idx < n ? set[idx] : NULL;
}

// Resolve the mnemonic, expanding the reg selected groups.
static const char *mnemonic(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned reg = (unsigned)(in->modrm >> 3) & 7u;
    if (map > 1)
        return map == 2 ? "esc38" : "esc3a";
    const char *base = map ? kOp0F[op].m : kOp1[op].m;
    if (!base)
        return "db";
    if (map == 1)
        return base[0] == 'g' ? pick(kGrp8, 8, reg) : base;
    if (!re_str_eq_cstr(re_str(base), "grp1"))
        return re_str_eq_cstr(re_str(base), "grp2")   ? pick(kGrp2, 8, reg)
               : re_str_eq_cstr(re_str(base), "grp3") ? pick(kGrp3, 8, reg)
               : re_str_eq_cstr(re_str(base), "grp4") ? pick(kGrp4, 2, reg)
                                                      : pick(kGrp5, 6, reg);
    return pick(kGrp1, 8, reg);
}

// The condition code a jcc, setcc or cmovcc carries, derived from the low three
// bits of the opcode. Every family shares the encoding, so this is the one place
// the table of conditions is written down.
static const char *condition(unsigned cc) {
    static const char *const k[16] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                      "s", "ns", "p", "np", "l", "ge", "le", "g"};
    return k[cc & 15u];
}

// A jcc, setcc or cmovcc mnemonic is the family stem plus the condition, so the
// rendered text is assembled rather than looked up.
static void put_cond(re_strbuf_t *out, const char *stem, const re_insn_t *in) {
    re_strbuf_puts(out, stem);
    re_strbuf_puts(out, condition(X64_ID_OP(in->insn_id) & 7u));
}

void x64_render(const re_insn_t *in, re_arena_t *a, re_strbuf_t *out) {
    const char *m = mnemonic(in);
    (void)a;
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    if (map == 0 && op >= 0x70 && op <= 0x7F) {
        put_cond(out, "j", in);
        re_strbuf_appendf(out, " 0x%llx", (unsigned long long)in->target);
        return;
    }
    if (map == 1 && op >= 0x80 && op <= 0x8F) {
        put_cond(out, "j", in);
        re_strbuf_appendf(out, " 0x%llx", (unsigned long long)in->target);
        return;
    }
    re_strbuf_puts(out, m ? m : "db");
}
