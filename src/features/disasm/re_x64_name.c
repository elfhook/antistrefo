// re_x64_name.c - the name of one instruction and the shape of its operand list.
// Module: feature (C11).
// Owns: the mnemonic decision, the ModRM selected tables, and the operand shape queries.
// Depends: re_x64_priv.h and the two opcode maps. Reads the record, never the bytes.
#include "features/disasm/re_x64_priv.h"

#include "features/disasm/re_x64_tab.h"
#include "features/disasm/re_x64_tab0f.h"
#include "utils/text/re_str.h"

// The group opcodes pick their mnemonic from the reg field, which is why the
// table only had a placeholder for them.
static const char *const kGrp1[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
static const char *const kGrp2[8] = {"rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"};
static const char *const kGrp3[8] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
static const char *const kGrp4[2] = {"inc", "dec"};
static const char *const kGrp5[6] = {"inc", "dec", "call", "lcall", "jmp", "ljmp"};

static const char *pick(const char *const *set, size_t n, unsigned idx) {
    return idx < n ? set[idx] : NULL;
}

// The opcode map holds one name per byte, so it can only be the name of the encoding
// that has no prefix. Everything else - the SIMD names the prefix decides, the groups
// that take their mnemonic from a ModRM field, the x87 escapes - is looked up in
// re_x64_simd.c, and a NULL there means the encoding has no name at all rather than a
// placeholder with a shape around it.
static const char *base_mnem(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    if (map > 1)
        return NULL;
    return map ? kOp0F[op].m : kOp1[op].m;
}

// True when the mnemonic the tables gave is a placeholder for a field selected
// group rather than a real name. Written as a test on the prefix because the groups
// are the only names in either table that start with "grp".
static bool is_placeholder(const char *b) {
    return b && b[0] == 'g' && b[1] == 'r' && b[2] == 'p';
}

// The 0F opcodes whose operand list is just the r/m operand, because the reg field
// carries the operation rather than an operand. A listing that prints the reg field as
// a register invents an operand, which is the difference between "rdrand eax" and
// "rdrand esi, eax".
bool x64_group0f_single(unsigned op) {
    return op == 0x00u || op == 0x01u || op == 0x0Du || op == 0x18u || op == 0x1Cu || op == 0x71u ||
           op == 0x72u || op == 0x73u || op == 0xAEu || op == 0xC7u;
}

// The 0F groups whose register form names an instruction that takes no operand at
// all: the fences, the virtual machine and monitor instructions, and the user mode
// ones. The bytes that are not one of those have no name, so suppressing the operand
// is right for every byte of these two opcodes.
bool x64_group0f_silent(const re_insn_t *in) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned reg = ((unsigned)in->modrm >> 3) & 7u;
    if (in->mod != 3)
        return false;
    // The segment status forms are the two register encodings of 0F 01 that read a
    // register, and the wait and monitor forms are the three prefixed ones of 0F AE
    // that read a register too. Everything else named in either byte takes none.
    if (op == 0x01u)
        return reg != 4u && reg != 6u;
    if (op != 0xAEu)
        return false;
    // The fences are the three register encodings of 0F AE that take no operand, and
    // lfence is the one of them whose byte is itself under any prefix at all.
    return in->pfx == 0u ? reg >= 5u : reg == 5u;
}

// Resolve the mnemonic, expanding the reg selected groups. Anything that is not
// a group keeps the mnemonic the table gave it, which is the whole point of
// having a table rather than a switch on the opcode.
const char *x64_text_mnemonic(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned reg = in->reg & 7u;
    const char *b = base_mnem(in);
    // F3 0F 1E FA and FB are endbr64 and endbr32: the landing pads a modern
    // compiler puts at the top of nearly every function. The opcode by itself is
    // only a hint nop, so calling it one hides where the function really starts.
    if (map == 1 && op == 0x1E && in->pfx == 2 && !in->vex &&
        (in->modrm == 0xFA || in->modrm == 0xFB))
        return in->modrm == 0xFA ? "endbr64" : "endbr32";
    // 0F 12 and 0F 16 are two instructions in one opcode: the memory form moves the
    // low or high half of an operand and the register form moves one between the two
    // halves of the same register. The table can hold one of the pair.
    if (map == 1 && !in->vex && in->pfx == 0 && in->mod == 3 && (op == 0x12u || op == 0x16u))
        return op == 0x12u ? "movhlps" : "movlhps";
    // 0F F0 is pshufd under 0x66 and lddqu under F2: one opcode, two names, and the
    // lddqu form carries no immediate, which is why the class is corrected as well.
    if (map == 1 && op == 0xF0u && in->pfx == 3u && !in->vex)
        return "lddqu";
    // 0F 6E and 0F 7E widen with REX.W, and a VEX encoding carries the same bit in its
    // own prefix, so the name says which width the operand has either way.
    if (map == 1 && (op == 0x6Eu || op == 0x7Eu) && ((in->rex & 8u) || in->vex_w))
        return "movq";
    // The 3DNow operations are all one opcode whose real meaning is in the byte after
    // the ModRM, and the registers they operate on are the mmx ones.
    if (map == 1 && op == 0x0Fu && !in->vex)
        return x64_grp0f_mnem(op, in->modrm, in->imm, in->is_mem, in->pfx);
    // F3 0F BC and F3 0F BD are the count trailing and leading zeros instructions of
    // the bit manipulation extensions: the same bytes without the prefix are bsf and
    // bsr, which count from the other end and are a different instruction.
    if (map == 1 && op == 0xBCu && in->pfx == 2u)
        return "tzcnt";
    if (map == 1 && op == 0xBDu && in->pfx == 2u)
        return "lzcnt";
    // F3 0F 09 is the no invalidate variant of wbinvd, which the prefix is what
    // makes distinguishable from the original.
    if (map == 1 && op == 0x09u && in->pfx == 2u)
        return "wbnoinvd";
    // The bounds moves name a memory operand: a register operand is reserved where the
    // byte is only bndldx, bndstx, bndmk or bndcn, and defined where it is bndmov,
    // bndcl or bndcu. The 0x66 form is the one of those that has both halves.
    if (map == 1 && (op == 0x1Au || op == 0x1Bu) && in->mod == 3u && in->pfx != 1u &&
        !(op == 0x1Au && in->pfx >= 2u))
        return NULL;
    // VEX 0F3A F0 with the F2 prefix is rorx, the one rotate the bit manipulation
    // extensions put in the 0F3A map. It has no other prefix form at all.
    if (map == 3 && op == 0xF0u && in->pfx == 3u)
        return "rorx";
    // The maps 2 and 3 have no names in the opcode map at all, and the x87 escapes
    // take theirs from a ModRM field, so both are resolved before the table's name is
    // even consulted.
    if (map == 2 || map == 3)
        return x64_simd_mnem((uint8_t)map, op, in->pfx);
    if (map == 0 && op >= 0xD8u && op <= 0xDFu) {
        uint8_t shape = 0;
        uint8_t st = 0;
        return x64_x87_mnem((uint8_t)op, in->modrm, in->is_mem, &shape, &st);
    }
    // The string primitives narrow to a 16-bit form under 0x66 and are dword wide
    // otherwise, and the table cannot say which because it holds one name per
    // opcode. Neither half of the pair is the unmodified name.
    if (map == 0 && (op == 0x6D || op == 0x6F))
        return in->pfx == 1 ? (op == 0x6D ? "insw" : "outsw") : (op == 0x6D ? "insd" : "outsd");
    if (map == 0 && op == 0xCF)
        return "iretq"; // 64-bit mode has no other iret
    // 0x98 and 0x99 sign extend one register into a wider pair, and the table holds
    // one name for the three widths. The operand size is what says whether the pair
    // is cbw and cwd, cwde and cdq, or cdqe and cqo.
    if (map == 0 && (op == 0x98u || op == 0x99u)) {
        if (in->opsize == 8u)
            return op == 0x98u ? "cdqe" : "cqo";
        if (in->opsize == 2u)
            return op == 0x98u ? "cbw" : "cwd";
        return op == 0x98u ? "cwde" : "cdq";
    }
    if (map == 0 && op == 0xE3)
        return "jrcxz"; // the loop counter is rcx, not cx, even though the encoding is shared
    if (map == 1) {
        const char *s = x64_simd_mnem(1, op, in->pfx);
        if (s)
            return s;
        // A group opcode's real name is in a ModRM field, and an opcode whose names
        // the prefix decides has no name when that prefix has no form of it. Both
        // are NULL here rather than a placeholder or a form of another prefix.
        if (is_placeholder(b))
            return x64_grp0f_mnem(op, in->modrm, in->imm, in->is_mem, in->pfx);
        // An opcode whose operands are not vector registers has no VEX form at all:
        // the AVX-512 encodings that reach this map for the mask registers and the
        // system forms are not the legacy instruction with a v in front of it, and the
        // table holds the legacy name alone, so neither name is right for them.
        if (x64_simd_known(1, op) || (in->vex && in->reg < RE_X64_XMM_BASE))
            return NULL;
        return b;
    }
    // The one byte map's group opcodes are the last names resolved from a ModRM
    // field. Every other opcode has its name in the table by this point.
    if (!b)
        return NULL;
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

// Does this form print an immediate? The opcode decides, not whether the immediate
// happens to be non zero: "and qword [rax+0x18], 0" and "mov eax, 0" both have a
// meaningful zero operand, and dropping it would make the listing disagree with the
// bytes it claims to be showing. The x87 escapes and the 3DNow selector are named by
// their immediate rather than carrying one, so neither appears here.
bool x64_text_has_imm(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    if (map == 1)
        return op == 0x70u || op == 0x71u || op == 0x72u || op == 0x73u || op == 0xBAu ||
               op == 0xC2u || op == 0xC4u || op == 0xC5u || op == 0xC6u ||
               (op == 0xF0u && in->pfx == 1u);
    if (map == 3)
        return true; // the whole 0F3A map is a ModRM form with an imm8 behind it
    if (map != 0)
        return false;
    if (op >= 0x80u && op <= 0x83u)
        return true;
    if (op <= 0x3Du)
        return (op & 7u) == 4u || (op & 7u) == 5u;
    // 0xB8 through 0xBF are the 32-bit half of the same mov block as 0xB0..0xB7 and
    // carry an immediate just the same. Leaving them out rendered every mov reg,
    // imm32 in the file as a bare "mov" with no operands.
    if (op == 0x68u || op == 0x69u || op == 0x6Au || (op >= 0xB0u && op <= 0xBFu) || op == 0xC6u ||
        op == 0xC7u)
        return true;
    return op == 0x81u || op == 0xA9u || op == 0xC0u || op == 0xC1u || op == 0xF6u || op == 0xF7u;
}

// The SIMD opcodes whose r/m operand is the destination. A listing that swaps them
// shows a load where the bytes are a store, which is the kind of mistake a reader
// only finds when they act on it.
bool x64_simd_store(unsigned op, uint8_t pfx) {
    switch (op) {
        case 0x11u: // movups and the other stores
        case 0x13u:
        case 0x17u:
        case 0x29u:
        case 0x2Bu:
        case 0x7Fu: // movdqa and movdqu
        case 0xD6u: // movq
        case 0xC3u: // movnti, which stores a general purpose register
        case 0xC5u: // pextrw writes to a general purpose register
            return true;
        case 0x7Eu:
            return pfx == 0 || pfx == 1; // movd and movq store; F3 0F 7E is the load
        default:
            return false;
    }
}

// True when the ModRM reg field selects an operation rather than naming an
// operand. On these the reg field is the sub opcode, so printing it as a register
// turns "sub rsp, 0x30" into "sub rbp, rsp, 0x30" and invents an operand.
bool x64_is_group_op(const re_insn_t *in) {
    unsigned map = X64_ID_MAP(in->insn_id);
    unsigned op = X64_ID_OP(in->insn_id);
    if (map == 1)
        return op == 0xBA || op == 0x71 || op == 0x72 || op == 0x73;
    if (map != 0)
        return false;
    return (op >= 0x80 && op <= 0x83) || (op >= 0xC0 && op <= 0xC1) || (op >= 0xD0 && op <= 0xD3) ||
           op == 0xF6 || op == 0xF7 || op == 0xFE || op == 0xFF || op == 0xC6 || op == 0xC7;
}

// The register an instruction encodes in its opcode rather than in a ModRM byte.
// The accumulator forms carry it as al or ax, and the mov block 0xB0..0xBF carries it
// as the low three bits of the opcode. Returns false when there is none, in which
// case the operand is left off rather than guessed.
bool x64_implicit_reg(const re_insn_t *in, unsigned *reg, uint8_t *force_size) {
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
    // A8 and A9 are test al, imm8 and test eax, imm32. They are the accumulator form
    // of the arithmetic block above, and the low three bits do not cover them: that
    // is why they used to render as a bare mnemonic with the immediate attached to it.
    if (op == 0xA8u || op == 0xA9u) {
        *reg = 0;
        *force_size = (op == 0xA8u) ? 1 : 0;
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

// The opcode that means emms without a prefix and vzeroupper or vzeroall with one.
// It is the one instruction whose VEX form is not the legacy name with a v in front,
// so it is the one that has to be spelled out.
const char *x64_text_vex_special(const re_insn_t *in) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned map = X64_ID_MAP(in->insn_id);
    if (map == 1 && op == 0x77u)
        return in->vex_l ? "vzeroall" : "vzeroupper";
    return NULL;
}

// The names of a jump or a move on a condition are the base plus a condition code,
// and the code is the low four bits of the opcode. One table per family, because the
// three families are the same encoding under three bases.
static const char *const kJcc[16] = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
};

static const char *const kCmov[16] = {
    "cmovo", "cmovno", "cmovb", "cmovae", "cmove", "cmovne", "cmovbe", "cmova",
    "cmovs", "cmovns", "cmovp", "cmovnp", "cmovl", "cmovge", "cmovle", "cmovg",
};

// The two families the renderer names itself rather than reading from a table that
// holds one name per opcode byte, because the byte alone does not decide them.
const char *x64_text_jcc(unsigned op) {
    return kJcc[op & 15u];
}

const char *x64_text_cmov(unsigned op) {
    return kCmov[op & 15u];
}
