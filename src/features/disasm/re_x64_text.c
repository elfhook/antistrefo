// re_x64_text.c - renders one projected x86-64 instruction as text.
// Module: feature (C11).
// Owns: mnemonic selection for the group opcodes and the operand formatting.
// Depends: re_x64_priv.h and the opcode tables. Never reads the image.
#include "features/disasm/re_x64_priv.h"

#include "features/disasm/re_x64_tab.h"
#include "features/disasm/re_x64_tab0f.h"
#include "utils/text/re_strbuf.h"

// The group opcodes pick their mnemonic from the reg field, which is why the
// table only had a placeholder for them.
static const char *const kGrp1[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
static const char *const kGrp2[8] = {"rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"};
static const char *const kGrp3[8] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
static const char *const kGrp4[2] = {"inc", "dec"};
static const char *const kGrp5[6] = {"inc", "dec", "call", "lcall", "jmp", "ljmp"};
static const char *const kGrp8[8] = {"", "", "", "", "bt", "bts", "btr", "btc"};

// The condition codes a jcc, setcc or cmovcc carry, from the low three bits of the
// opcode. Every family shares the encoding, so this is the one place they appear.
static const char *const kCond[16] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                      "s", "ns", "p", "np", "l", "ge", "le", "g"};

static const char *pick(const char *const *set, size_t n, unsigned idx) {
    return idx < n ? set[idx] : NULL;
}

static const char *base_mnem(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    if (map > 1)
        return map == 2 ? "esc38" : "esc3a";
    return map ? kOp0F[op].m : kOp1[op].m;
}

// Resolve the mnemonic, expanding the reg selected groups. Anything that is not
// a group keeps the mnemonic the table gave it, which is the whole point of
// having a table rather than a switch on the opcode.
static const char *mnemonic(const re_insn_t *in) {
    unsigned reg = in->reg & 7u;
    const char *b = base_mnem(in);
    if (!b)
        return "db";
    if (X64_ID_MAP(in->insn_id) == 1)
        return b[0] == 'g' ? pick(kGrp8, 8, reg) : b;
    if (re_str_eq_cstr(re_str(b), "grp1"))
        return pick(kGrp1, 8, reg);
    if (re_str_eq_cstr(re_str(b), "grp2"))
        return pick(kGrp2, 8, reg);
    if (re_str_eq_cstr(re_str(b), "grp3"))
        return pick(kGrp3, 8, reg);
    if (re_str_eq_cstr(re_str(b), "grp4"))
        return pick(kGrp4, 2, reg);
    if (re_str_eq_cstr(re_str(b), "grp5"))
        return pick(kGrp5, 6, reg);
    if (re_str_eq_cstr(re_str(b), "grp11"))
        return "mov";
    return b;
}

// A size keyword, the way a disassembler spells a narrow access. A dword
// register and a qword register are implied by the name, so only the narrow ones
// and any mismatch need spelling out.
static const char *size_kw(const re_insn_t *in, unsigned reg_bytes) {
    if (reg_bytes == 1)
        return in->opsize == 2 ? "word ptr " : "byte ptr ";
    if (reg_bytes == 2 && in->opsize != 2)
        return in->opsize == 1 ? "" : "dword ptr ";
    if (in->opsize == 1)
        return "dword ptr ";
    return "";
}

// Does this form print an immediate? The opcode decides, not whether the immediate
// happens to be non zero: "and qword [rax+0x18], 0" and "mov eax, 0" both have a
// meaningful zero operand, and dropping it would make the listing disagree with the
// bytes it claims to be showing.
static bool form_has_imm(const re_insn_t *in) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    if (map == 0 && op >= 0x80 && op <= 0x83)
        return true;
    if (map == 0 && op <= 0x3D)
        return (op & 7u) == 4u || (op & 7u) == 5u;
    // 0xB8 through 0xBF are the 32-bit half of the same mov block as 0xB0..0xB7 and
    // carry an immediate just the same. Leaving them out rendered every mov reg,
    // imm32 in the file as a bare "mov" with no operands.
    if (map == 0 &&
        (op == 0x68 || op == 0x6A || (op >= 0xB0 && op <= 0xBF) || op == 0xC6 || op == 0xC7))
        return true;
    return (op == 0x81 || op == 0xA9 || op == 0xBA || op == 0xC1 || op == 0xF6 || op == 0xF7);
}

static void put_reg(re_strbuf_t *out, const re_insn_t *in, unsigned reg) {
    const char *n = x64_reg_name_ex(reg, (uint8_t)in->opsize, in->rex);
    re_strbuf_puts(out, n ? n : "?");
}

// [base + index * scale + disp], in the order a person writes it.
static void put_mem(re_strbuf_t *out, const re_insn_t *in) {
    if (in->has_mem && in->base == RE_REG_RIP) {
        re_strbuf_puts(out, "[rip");
        if (in->disp)
            re_strbuf_appendf(out, "%c0x%llx", in->disp < 0 ? '-' : '+',
                              (unsigned long long)(in->disp < 0 ? -in->disp : in->disp));
        re_strbuf_puts(out, "]");
        return;
    }
    re_strbuf_puts(out, "[");
    if (in->base != RE_REG_NONE)
        put_reg(out, in, in->base);
    if (in->index != RE_REG_NONE) {
        if (in->base != RE_REG_NONE)
            re_strbuf_puts(out, " + ");
        put_reg(out, in, in->index);
        if (in->scale > 1)
            re_strbuf_appendf(out, "*%u", in->scale);
    }
    if (in->disp) {
        if (in->base == RE_REG_NONE && in->index == RE_REG_NONE)
            re_strbuf_appendf(out, "0x%llx", (unsigned long long)in->disp);
        else
            re_strbuf_appendf(out, "%c0x%llx", in->disp < 0 ? '-' : '+',
                              (unsigned long long)(in->disp < 0 ? -in->disp : in->disp));
    }
    re_strbuf_puts(out, "]");
}

// The r/m operand, which is a register or a memory reference depending on the mod
// field, and the reg operand, which is always a register.
static void put_rm(re_strbuf_t *out, const re_insn_t *in) {
    if (!in->is_mem) {
        put_reg(out, in, in->rm);
        return;
    }
    re_strbuf_puts(out, size_kw(in, in->opsize));
    put_mem(out, in);
}

// The immediate's width decides how it reads. A 32-bit immediate is a bit pattern,
// and the decoder has already sign extended it to fill an int64, so printing that
// directly turns "mov edi, 0xdeadbeef" into "mov edi, -0x21524111" - a different
// number from the one the instruction carries. Only a genuine 64-bit immediate keeps
// its sign, because there the sign is part of the value.
static void put_imm_sz(re_strbuf_t *out, int64_t v, uint8_t opsize) {
    if (opsize && opsize < 8) {
        uint64_t mask = (1ull << (opsize * 8u)) - 1ull;
        re_strbuf_appendf(out, "0x%llx", (unsigned long long)((uint64_t)v & mask));
        return;
    }
    if (v < 0)
        re_strbuf_appendf(out, "-0x%llx", (unsigned long long)(-v));
    else
        re_strbuf_appendf(out, "0x%llx", (unsigned long long)v);
}

static void put_imm(re_strbuf_t *out, const re_insn_t *in) {
    put_imm_sz(out, in->imm, in->opsize);
}

// True when the ModRM reg field selects an operation rather than naming an
// operand. On these the reg field is the sub opcode, so printing it as a register
// turns "sub rsp, 0x30" into "sub rbp, rsp, 0x30" and invents an operand.
static bool is_group(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    if (map == 1)
        return op == 0xBA;
    if (map != 0)
        return false;
    return (op >= 0x80 && op <= 0x83) || (op >= 0xC0 && op <= 0xC1) || (op >= 0xD0 && op <= 0xD3) ||
           op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF || op == 0xC6 || op == 0xC7;
}

// The register an instruction encodes in its opcode rather than in a ModRM byte.
// The accumulator forms carry it as al or ax, and the mov block 0xB0..0xBF carries it
// as the low three bits of the opcode. Returns false when there is none, in which
// case the operand is left off rather than guessed.
static bool implicit_reg(const re_insn_t *in, unsigned *reg, uint8_t *force_size) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    *force_size = 0;
    if (map != 0)
        return false;
    // 04 05 0C 0D ... 3C 3D: add, or, adc, sbb, and, sub, xor and cmp against al, ax,
    // eax or rax. The even opcode is the byte form, the odd one the wider form.
    if (op <= 0x3D && ((op & 7u) == 4u || (op & 7u) == 5u)) {
        *reg = 0;
        *force_size = (op & 1u) ? 0 : 1; // 0 leaves the decoded size alone
        return true;
    }
    // B0..B7 is mov r8, imm8 and B8..BF is mov r32, imm32. Both runs put the register
    // in the low three bits, so the register is not op minus 0xB0 any more than push's
    // register is op minus 0x50.
    if (op >= 0xB0u && op <= 0xBFu) {
        *reg = (op & 0x07u) + ((in->rex & 1u) ? 8u : 0u);
        *force_size = (op <= 0xB7u) ? 1 : 0;
        return true;
    }
    return false;
}

// The operand forms, in the order x86 defines them. Most integer instructions are
// one of these five, and a form that is not recognised is left off rather than
// guessed, which is why the text is sometimes just a mnemonic.
static void put_operands(re_strbuf_t *out, const re_insn_t *in, const char *m) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    if (in->is_call || in->is_branch) {
        re_strbuf_puts(out, " ");
        if (in->has_target)
            re_strbuf_appendf(out, "0x%llx", (unsigned long long)in->target);
        else if (in->has_mem)
            put_mem(out, in);
        return;
    }
    if (!in->has_modrm) {
        if (map == 0 && op >= 0x50 && op <= 0x5F) {
            // The low three bits pick the register, not op minus 0x50. The block is
            // two runs of eight - push rax..rdi then pop rax..rdi - so subtracting
            // 0x50 renders pop rdi as r15.
            unsigned r = (op & 0x07u) + ((in->rex & 1u) ? 8u : 0u);
            re_strbuf_puts(out, " ");
            put_reg(out, in, r);
            return;
        }
        unsigned r = 0;
        uint8_t forced = 0;
        if (implicit_reg(in, &r, &forced)) {
            re_insn_t v = *in; // a byte form needs its own size to name the register
            if (forced)
                v.opsize = forced;
            re_strbuf_puts(out, " ");
            put_reg(out, &v, r);
            re_strbuf_puts(out, ", ");
            put_imm(out, in);
            return;
        }
        if (form_has_imm(in))
            put_imm(out, in);
        return;
    }
    if (map == 0 && op == 0x8D) { // lea
        re_strbuf_puts(out, " ");
        put_reg(out, in, in->reg);
        re_strbuf_puts(out, ", ");
        put_mem(out, in);
        return;
    }
    re_strbuf_puts(out, " ");
    if (is_group(in)) {
        put_rm(out, in);
        if (form_has_imm(in)) {
            re_strbuf_puts(out, ", ");
            put_imm(out, in);
        }
        return;
    }
    // r/m first when the reg field is the destination, which is the AT&T order and
    // also the order that puts the mnemonic in the middle the way a reader scans.
    bool reg_first = (map == 0 && (op == 0x89 || op == 0xC6 || op == 0x88)) ||
                     (map == 1 && op >= 0x90 && op <= 0x9F) || (map == 0 && op == 0x63);
    if (reg_first) {
        put_rm(out, in);
        re_strbuf_puts(out, ", ");
        put_reg(out, in, in->reg);
    } else {
        put_reg(out, in, in->reg);
        re_strbuf_puts(out, ", ");
        put_rm(out, in);
    }
    if (in->imm) {
        re_strbuf_puts(out, ", ");
        put_imm(out, in);
    }
    (void)m;
}

void x64_render(const re_insn_t *in, re_arena_t *a, re_strbuf_t *out) {
    const char *m = mnemonic(in);
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    (void)a;
    if (map == 0 && op >= 0x70 && op <= 0x7F) {
        re_strbuf_putc(out, 'j');
        re_strbuf_puts(out, kCond[op & 7u]);
    } else if (map == 1 && op >= 0x80 && op <= 0x8F) {
        re_strbuf_putc(out, 'j');
        re_strbuf_puts(out, kCond[op & 7u]);
    } else {
        re_strbuf_puts(out, m ? m : "db");
    }
    put_operands(out, in, m);
}
