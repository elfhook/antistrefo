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
            if (c == 0x66)
                *osize = true;
            if (c == 0x67)
                *asize = true;
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
    unsigned k;
    for (k = 0; k < payload; k++) {
        uint8_t b;
        if (!rd8(p, n, i, &b))
            return false;
        if (k == 0)
            first = b;
    }
    if (payload == 1u) {
        unsigned pp = (unsigned)(first & 3u);
        in->map = (uint8_t)(pp ? pp : 1u);
    } else {
        in->map = (uint8_t)(first & (payload == 3u ? 0x07u : 0x1Fu));
    }
    if (in->map < 1 || in->map > 3)
        return false;
    if (!rd8(p, n, i, &in->opcode))
        return false;
    in->vex = true;
    return true;
}

// The class for a resolved map and opcode, or false when the encoding is not valid
// in 64-bit mode. The 0F38 and 0F3A maps are all ModRM by construction.
static bool x64_class(uint8_t map, uint8_t op, uint8_t *cls) {
    if (map == 2) {
        *cls = XC_MODRM;
        return true;
    }
    if (map == 3) {
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

// ModRM, and the SIB and displacement it drags in. RIP relative addressing is the
// one case worth flagging, because it is how a 64-bit binary points at its own data.
static bool x64_modrm(const uint8_t *p, size_t n, size_t *i, x64_insn_t *in) {
    uint8_t modrm;
    unsigned mod;
    unsigned rm;
    if (!rd8(p, n, i, &modrm))
        return false;
    in->modrm = modrm;
    mod = (unsigned)(modrm >> 6);
    rm = (unsigned)(modrm & 7u);
    if (mod == 3)
        return true;
    if (mod == 0 && rm == 5) {
        // With a 64-bit address this is RIP relative; with a 32-bit one it is a
        // plain absolute address, and either way it costs four displacement bytes.
        uint64_t d = 0;
        if (!rdn(p, n, i, 4, &d))
            return false;
        in->rip_rel = in->addrsize == 8;
        // Signed, because a reference backwards to an earlier table or string is
        // the common case and an unsigned displacement would point a gigabyte away.
        if (in->rip_rel)
            in->disp = (int64_t)(int32_t)(uint32_t)d;
        return true;
    }
    if (rm == 4) {
        uint8_t sib;
        if (!rd8(p, n, i, &sib))
            return false;
        if (mod == 0 && (unsigned)(sib & 7u) == 5u)
            return rdn(p, n, i, 4, &(uint64_t){0});
    }
    if (mod == 1)
        return rdn(p, n, i, 1, &(uint64_t){0});
    if (mod == 2)
        return rdn(p, n, i, 4, &(uint64_t){0});
    return true;
}

// Immediate width in bytes. The 0x66 prefix narrows 16 and 32, and REX.W widens
// only the encodings that have a 64-bit form, which is why XC_IV is separate.
static unsigned x64_imm_bytes(const x64_insn_t *in) {
    bool w = (in->rex & 0x08u) != 0;
    bool d = (in->rex & 0x0Eu) == 0x0Eu; // a bare 0x66 or 0x67 became a REX
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
            return 8;
        case XC_IZ:
        case XC_MODRM_IZ:
        case XC_REL32:
            return d ? 2u : 4u;
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
           cls == XC_MODRM_IZB || cls == XC_MODRM_F6 || cls == XC_MODRM_F7 || cls == XC_3DNOW;
}

static bool is_relative(uint8_t cls) {
    return cls == XC_REL8 || cls == XC_REL32;
}

// A zeroed record, so every field is defined before anything reads it. Leaving
// one to chance is how a stale stack value decides an instruction's length.
static void blank(x64_insn_t *in) {
    in->cls = XC_BAD;
    in->modrm = 0;
    in->has_modrm = false;
    in->rex = 0;
    in->map = 0;
    in->opcode = 0;
    in->size = 0;
    in->opsize = 4;
    in->addrsize = 8;
    in->rip_rel = false;
    in->vex = false;
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
    if (in.rex == 0x66)
        osize = true;
    if (in.rex == 0x67)
        asize = true;
    if (!x64_opcode(p, n, &i, &in))
        return false;
    if (!x64_class(in.map, in.opcode, &in.cls))
        return false;
    in.opsize = (uint8_t)((in.rex & 0x08u) ? 8u : (osize ? 2u : 4u));
    in.addrsize = (uint8_t)(asize ? 4u : 8u);
    if (has_modrm(in.cls)) {
        if (!x64_modrm(p, n, &i, &in))
            return false;
        in.has_modrm = true;
    }
    if (!x64_finish(p, n, i, addr, &in))
        return false;
    *out = in;
    return true;
}
