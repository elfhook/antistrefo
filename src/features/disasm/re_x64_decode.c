// re_x64_decode.c - the x86-64 length decoder. It walks one instruction and stops.
// Module: feature (C11).
// Owns: prefix, opcode, ModRM, SIB, displacement and immediate length decoding.
// Depends: re_x64_priv.h and the two opcode tables. Every read is bounds checked
// against the span it was handed, so a truncated instruction fails instead of
// reading past the end, and an unknown opcode fails instead of guessing a length.
#include "features/disasm/re_x64_priv.h"

#include "features/disasm/re_x64_tab.h"
#include "features/disasm/re_x64_tab0f.h"

#define X64_MAX_PREFIX 15

// One byte, bounds checked. A false return means the instruction is truncated.
static bool rd8(const uint8_t *p, size_t n, size_t *i, uint8_t *out) {
    if (*i >= n)
        return false;
    *out = p[(*i)++];
    return true;
}

// k little endian bytes, bounds checked. Little endian is the only order x86
// stores memory in, so there is no big endian path to keep honest.
static bool rdn(const uint8_t *p, size_t n, size_t *i, unsigned k, uint64_t *out) {
    uint64_t v = 0;
    unsigned b;
    for (b = 0; b < k; b++) {
        uint8_t c;
        if (!rd8(p, n, i, &c))
            return false;
        v |= (uint64_t)c << (8u * b);
    }
    *out = v;
    return true;
}

static bool is_legacy_prefix(uint8_t c) {
    return c == 0xF0 || c == 0xF2 || c == 0xF3 || c == 0x2E || c == 0x36 || c == 0x3E ||
           c == 0x26 || c == 0x64 || c == 0x65 || c == 0x66 || c == 0x67;
}

// Legacy prefixes and REX. A REX byte is void when a legacy prefix follows it, so
// the register is cleared rather than kept, and that is why the order matters.
static bool x64_legacy(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in, bool *osize,
                       bool *asize) {
    size_t taken = 0;
    uint8_t c;
    for (;;) {
        if (!rd8(p, n, i, &c))
            return false;
        if (is_legacy_prefix(c)) {
            in->rex = 0;
            if (c == 0x66) {
                *osize = true;
                in->pfx = 1;
            }
            if (c == 0x67)
                *asize = true;
            // F3 and F2 are the SIMD prefixes as well as rep and repne. Which one
            // it is decides the instruction in the whole 0F 10 to 0F FF block, so
            // the last one seen is kept rather than only the boolean they used to
            // collapse into.
            if (c == 0xF3)
                in->pfx = 2;
            if (c == 0xF2)
                in->pfx = 3;
            if (++taken > X64_MAX_PREFIX)
                return false;
            continue;
        }
        if (c >= 0x40 && c <= 0x4F) {
            in->rex = c;
            continue;
        }
        (*i)--;
        return true;
    }
}

// VEX2, VEX3 and EVEX, which stand in for the escape byte and are followed by an
// opcode. The map field sits in a different place in each encoding: VEX3 and EVEX
// carry an explicit mmmmm, but VEX2 has only pp, where zero means the 0F map. The
// trailing payload byte is a register specifier and is skipped.
static bool x64_vex(const uint8_t *p, size_t n, size_t *i, uint8_t esc, x64_insn_t *in) {
    unsigned payload = (esc == 0xC5) ? 1u : (esc == 0xC4) ? 2u : 3u;
    uint8_t first = 0;
    uint8_t second = 0;
    unsigned k;
    for (k = 0; k < payload; k++) {
        uint8_t b;
        if (!rd8(p, n, i, &b))
            return false;
        if (k == 0)
            first = b;
        else if (k == 1)
            second = b;
    }
    // The third operand is stored ones' complement in every one of the three
    // encodings, so it is complemented back here. Rendering the stored value
    // names the wrong register for every AVX instruction with three operands.
    in->vex_vvvv = (uint8_t)((~((payload == 1u ? first : second) >> 3)) & 0x0Fu);
    // The length bit: zero is 128 bit and one is 256. It is what decides whether the
    // registers a VEX instruction names are xmm or ymm, and it sits in the same place
    // in all three encodings.
    in->vex_l = (((payload == 1u ? first : second) & 0x04u) != 0);
    // The W bit widens the operands exactly the way REX.W does, and it sits in bit
    // seven of the second byte of VEX3 and EVEX. VEX2 carries no W bit at all.
    in->vex_w = (payload > 1u) && ((second & 0x80u) != 0);
    if (payload == 1u) {
        // VEX2 carries no map field at all: what it carries is pp, the prefix the
        // encoding implies, and the map is always 0F. Reading pp as the map sent
        // every F2 and F3 form into the 0F38 and 0F3A maps, where the 0F3A rule
        // added an immediate the instruction does not have.
        in->vex_pp = (uint8_t)(first & 3u);
        in->map = 1;
    } else {
        in->map = (uint8_t)(first & (payload == 3u ? 0x07u : 0x1Fu));
        in->vex_pp = (uint8_t)(second & 3u);
    }
    in->pfx = in->vex_pp;
    // 4 is not a map any encoding uses. 5 and 6 are EVEX only, and refusing them
    // ended the walk on every AVX-512 instruction that used them.
    if (in->map < 1 || in->map == 4 || (in->map > 6) || (in->map > 3 && payload != 3u))
        return false;
    if (!rd8(p, n, i, &in->opcode))
        return false;
    in->vex = true;
    return true;
}

// The class for a resolved map and opcode, or false when the encoding is not valid
// in 64-bit mode. The 0F38 and 0F3A maps are all ModRM by construction.
static bool x64_class(uint8_t map, uint8_t op, uint8_t *cls) {
    if (map == 2 || map == 5) {
        *cls = XC_MODRM;
        return true;
    }
    if (map == 3 || map == 6) {
        *cls = XC_MODRM_IB;
        return true;
    }
    if (map > 1)
        return false;
    uint8_t c = map ? kOp0F[op].cls : kOp1[op].cls;
    if (c == XC_BAD)
        return false;
    *cls = c;
    return true;
}

// mod zero with rm 5 is the RIP relative form in 64-bit mode and a plain absolute
// address in 32-bit mode. Either way it costs four displacement bytes.
static bool x64_rip_rel(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in) {
    uint64_t d = 0;
    if (!rdn(p, n, i, 4, &d))
        return false;
    in->rip_rel = in->addrsize == 8;
    // Signed, because a reference backwards to an earlier table or string is the
    // common case and an unsigned displacement would point a gigabyte away.
    if (in->rip_rel) {
        in->disp = (int64_t)(int32_t)(uint32_t)d;
        in->base = RE_REG_RIP;
    }
    return true;
}

// The SIB byte, which supplies the scale, the index and sometimes the base. A SIB
// with no base and mod zero is a pure displacement, which sets *done because that
// displacement is the whole address and the caller must not add a second one.
static bool x64_sib(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in, unsigned mod,
                    uint8_t rex_x, uint8_t rex_b, bool *done) {
    uint8_t sib;
    *done = false;
    if (!rd8(p, n, i, &sib))
        return false;
    in->scale = (uint8_t)(1u << ((unsigned)(sib >> 6) & 3u));
    // Index field 4 means no index at all, unless REX.X says otherwise. Reading
    // it as esp instead is how an operand ends up naming the same register twice.
    if (((unsigned)(sib >> 3) & 7u) == 4u && rex_x == 0)
        in->index = RE_REG_NONE;
    else
        in->index = (uint8_t)(((unsigned)(sib >> 3) & 7u) + rex_x);
    if (mod == 0 && (unsigned)(sib & 7u) == 5u) {
        uint64_t d = 0;
        if (!rdn(p, n, i, 4, &d))
            return false;
        in->disp = (int64_t)(int32_t)(uint32_t)d;
        in->base = RE_REG_NONE;
        *done = true;
        return true;
    }
    in->base = (uint8_t)(((unsigned)(sib & 7u) + rex_b));
    return true;
}

// The displacement, whose width the mod field fixes: none, one byte, or four.
static bool x64_disp(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in, unsigned mod) {
    uint64_t d = 0;
    if (mod == 0)
        return true;
    if (mod == 1) {
        if (!rdn(p, n, i, 1, &d))
            return false;
        in->disp = (int64_t)(int8_t)(uint8_t)d;
        return true;
    }
    if (!rdn(p, n, i, 4, &d))
        return false;
    in->disp = (int64_t)(int32_t)(uint32_t)d;
    return true;
}

// ModRM, and the SIB and displacement it drags in. RIP relative addressing is the
// one case worth flagging, because it is how a 64-bit binary points at its own
// data. Every register number here is extended by REX.R or REX.B, so a consumer
// never has to remember to apply the prefix itself.
static bool x64_modrm(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in) {
    uint8_t modrm;
    unsigned mod;
    unsigned rm;
    uint8_t rex_r = (uint8_t)((in->rex & 0x04u) ? 8u : 0u);
    uint8_t rex_x = (uint8_t)((in->rex & 0x02u) ? 8u : 0u);
    uint8_t rex_b = (uint8_t)((in->rex & 0x01u) ? 8u : 0u);
    if (!rd8(p, n, i, &modrm))
        return false;
    in->modrm = modrm;
    mod = (unsigned)(modrm >> 6);
    rm = (unsigned)(modrm & 7u);
    in->mod = (uint8_t)mod;
    in->reg = (uint8_t)(((unsigned)(modrm >> 3) & 7u) + rex_r);
    in->rm = (uint8_t)(rm + rex_b);
    in->base = RE_REG_NONE;
    in->index = RE_REG_NONE;
    in->scale = 1;
    in->is_mem = mod != 3u;
    // The control and debug register moves ignore mod entirely: the byte after the
    // opcode is the whole operand encoding, and reading a displacement out of it
    // consumed the first bytes of the next instruction.
    if (in->cls == XC_MODRM_NOMEM)
        return true;
    if (mod == 3)
        return true;
    if (mod == 0 && rm == 5)
        return x64_rip_rel(p, n, i, in);
    if (rm == 4) {
        bool done = false;
        if (!x64_sib(p, n, i, in, mod, rex_x, rex_b, &done))
            return false;
        if (done)
            return true;
    } else {
        in->base = in->rm;
    }
    return x64_disp(p, n, i, in, mod);
}

// Immediate width in bytes. The 0x66 prefix narrows 16 and 32, and REX.W widens
// only the encodings that have a 64-bit form, which is why XC_IV is separate.
static unsigned x64_imm_bytes(const x64_insn_t *in) {
    bool w = (in->rex & 0x08u) != 0;
    // 0x66 narrows the immediate to 16 bits. This used to be guessed from the REX
    // byte, which has nothing to do with it: a 66-prefixed form was read as a
    // 32-bit one and every instruction after it was decoded from the wrong place.
    bool d = in->opsize == 2;
    switch (in->cls) {
        case XC_IB:
        case XC_IBS:
        case XC_MODRM_IB:
        case XC_MODRM_IZB:
        case XC_3DNOW:
            return 1;
        case XC_IW:
        case XC_MODRM_IW:
            return 2;
        case XC_PTR:
            // The absolute moves take a moffs whose width follows the address
            // size, not the operand size. With a 0x67 override they are four
            // bytes wide, and reading eight ate the front of the next
            // instruction in every 32-bit-addressed image region.
            return (in->addrsize == 4u) ? 4u : 8u;
        case XC_IZ:
        case XC_MODRM_IZ:
            return d ? 2u : 4u;
        case XC_REL32:
            // A near branch is 32 bits wide in 64-bit mode whatever the prefix
            // says. Shortening it by the operand size put every target of a
            // 66-prefixed jump four bytes off.
            return 4u;
        case XC_IV:
            return w ? 8u : (d ? 2u : 4u);
        case XC_REL8:
            return 1;
        case XC_IW_IB:
            return 3;
        case XC_MODRM_F6:
            return (((unsigned)(in->modrm >> 3) & 7u) <= 1u) ? 1u : 0u;
        case XC_MODRM_F7:
            return (((unsigned)(in->modrm >> 3) & 7u) <= 1u) ? (d ? 2u : 4u) : 0u;
        default:
            return 0;
    }
}

static bool has_modrm(uint8_t cls) {
    return cls == XC_MODRM || cls == XC_MODRM_IB || cls == XC_MODRM_IW || cls == XC_MODRM_IZ ||
           cls == XC_MODRM_IZB || cls == XC_MODRM_F6 || cls == XC_MODRM_F7 || cls == XC_3DNOW ||
           cls == XC_MODRM_NOMEM;
}

static bool is_relative(uint8_t cls) {
    return cls == XC_REL8 || cls == XC_REL32;
}

// Group opcodes whose ModRM reg field has no meaning outside a few values. The
// processor raises an invalid opcode fault on the rest, so decoding one invents an
// instruction out of the bytes that follow and the walk lands in the middle of the
// next one. Everything here was previously given the group's length whatever the
// reg field said, which is exactly the padding bytes in an executable section.
static bool x64_undef(const x64_insn_t *in) {
    unsigned reg;
    if (in->map != 0)
        return false;
    reg = ((unsigned)(in->modrm >> 3) & 7u);
    switch (in->opcode) {
        case 0x8F: // pop r/m64 is reg 0; the other seven are not encodings
            return reg != 0u;
        // Group 11. Reg 0 is the move; reg 7 is xabort or xbegin, and both have
        // exactly one encoding, the ModRM byte F8, with the immediate the operand.
        // Reg 1 to 6 have no meaning at all.
        case 0xC6:
        case 0xC7:
            return reg != 0u && (reg != 7u || in->modrm != 0xF8u);
        case 0xFE: // inc and dec, byte form
            return reg > 1u;
        case 0xFF:
            if (reg == 7u)
                return true; // no encoding at all
            // The far call and far jump name a memory operand, so mod 3 is
            // reserved. Reading it as a register form kept two bytes of a branch.
            if ((reg == 3u || reg == 5u) && in->mod == 3u)
                return true;
            return false;
        default:
            return false;
    }
}

// A zeroed record, so every field is defined before anything reads it. Leaving
// one to chance is how a stale stack value decides an instruction's length.
static void blank(x64_insn_t *in) {
    in->cls = XC_BAD;
    in->modrm = 0;
    in->has_modrm = false;
    in->reg = 0;
    in->rm = 0;
    in->mod = 0;
    in->base = RE_REG_NONE;
    in->index = RE_REG_NONE;
    in->scale = 1;
    in->is_mem = false;
    in->rex = 0;
    in->pfx = 0;
    in->vex_pp = 0;
    in->vex_vvvv = 0;
    in->map = 0;
    in->opcode = 0;
    in->size = 0;
    in->opsize = 4;
    in->addrsize = 8;
    in->rip_rel = false;
    in->vex = false;
    in->vex_l = false;
    in->vex_w = false;
    in->imm = 0;
    in->disp = 0;
    in->target = 0;
    in->mem = 0;
    in->has_target = false;
    in->id = 0;
}

// Resolve the opcode byte to a map, following 0F, 0F38 and 0F3A. Each root reads
// one more byte, and a vector prefix bypasses this because it names its own map.
static bool x64_opcode(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in) {
    uint8_t esc = 0;
    if (!rd8(p, n, i, &esc))
        return false;
    if (esc == 0xC5 || esc == 0xC4 || esc == 0x62)
        return x64_vex(p, n, i, esc, in);
    in->opcode = esc;
    for (;;) {
        if (in->map == 0 && in->opcode == 0x0F)
            in->map = 1;
        else if (in->map == 1 && (in->opcode == 0x38 || in->opcode == 0x3A))
            in->map = (in->opcode == 0x38) ? 2u : 3u;
        else
            return true;
        if (!rd8(p, n, i, &in->opcode))
            return false;
    }
}

// Read the immediate and, for a branch, resolve the target from the address the
// instruction sits at. A negative displacement has to sign extend from its own
// width or a backwards branch lands above the function instead of inside it.
static bool x64_finish(const uint8_t *p, size_t n, size_t i, uint64_t addr, x64_insn_t *in) {
    uint64_t imm = 0;
    unsigned nb = x64_imm_bytes(in);
    if (nb && !rdn(p, n, &i, nb, &imm))
        return false;
    if (nb) {
        unsigned shift = (nb < 8u) ? (8u * (8u - nb)) : 0u;
        in->imm = (int64_t)(imm << shift) >> shift;
    }
    if (is_relative(in->cls)) {
        in->target = addr + (uint64_t)i + (uint64_t)in->imm;
        in->has_target = true;
    }
    // The RIP relative address is only known once the whole instruction is, since
    // it counts from the end of the instruction rather than from the displacement.
    if (in->rip_rel)
        in->mem = addr + (uint64_t)i + (uint64_t)in->disp;
    in->id = X64_ID(in->map, in->opcode);
    in->size = (uint8_t)i;
    return i > 0 && i <= n && i <= RE_MAX_INSN_LEN;
}

bool x64_decode(const uint8_t *p, size_t n, uint64_t addr, x64_insn_t *out) {
    x64_insn_t in;
    size_t i = 0;
    bool osize = false;
    bool asize = false;
    blank(&in);
    if (!x64_legacy(p, n, &i, &in, &osize, &asize))
        return false;
    // 0x66 and 0x67 between the last REX and the opcode are REX bytes that decode
    // as the prefix they displaced, so they still narrow the sizes.
    if (in.rex == 0x66) {
        osize = true;
        in.pfx = 1;
    }
    if (in.rex == 0x67)
        asize = true;
    if (!x64_opcode(p, n, &i, &in))
        return false;
    if (!x64_class(in.map, in.opcode, &in.cls))
        return false;
    in.opsize = (uint8_t)((in.rex & 0x08u) ? 8u : (osize ? 2u : 4u));
    in.addrsize = (uint8_t)(asize ? 4u : 8u);
    // F2 0F F0 is lddqu, which loads a line and carries no immediate, while 66 0F
    // F0 is pshufd, which carries one. The class table holds one class per opcode,
    // so the prefix decides this one.
    if (in.map == 1 && in.opcode == 0xF0u && (in.pfx == 3u || in.vex_pp == 3u))
        in.cls = XC_MODRM;
    if (has_modrm(in.cls)) {
        if (!x64_modrm(p, n, &i, &in))
            return false;
        in.has_modrm = true;
    }
    if (x64_undef(&in))
        return false;
    // Push and pop are the documented exception to the 32-bit default: in 64-bit
    // mode their default operand size is 64, and the 32-bit form needs a mode switch
    // rather than a prefix. Without this, 50 rendered as "push eax" where it is
    // "push rax" and 5f as "pop r15d" where it is "pop rdi". The lengths were already
    // right, which is why only the operand names were wrong.
    if (in.map == 0 && in.opcode >= 0x50u && in.opcode <= 0x5Fu)
        in.opsize = 8;
    if (!x64_finish(p, n, i, addr, &in))
        return false;
    *out = in;
    return true;
}
