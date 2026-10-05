// re_x64_x87.c - the x87 escape names and the operands they print.
// Module: feature (C11).
// Owns: the escape tables, the name lookup that reads them, and the x87 operand text.
// Depends: re_x64_priv.h and re_strbuf. A table lookup, never a composed name.
#include "features/disasm/re_x64_priv.h"

#include "utils/text/re_strbuf.h"

// The x87 escapes. D8 through DF each hold eight memory forms selected by the reg
// field; the register forms of the same escape are a different set of opcodes, read
// out of the tables below. A NULL name means the encoding has no meaning.
static const char *const kX87Mem[8][8] = {
    {"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"},         // D8
    {"fld", "fisttp", "fst", "fstp", "fldenv", "fldcw", "fnstenv", "fnstcw"},    // D9
    {"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"}, // DA
    {"fild", "fisttp", "fist", "fistp", "fld", "fistp", "fstp", "fstp"},         // DB
    {"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"},         // DC
    {"fld", "fisttp", "fst", "fstp", "frstor", "fstp", "fsave", "fnstsw"},       // DD
    {"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"}, // DE
    {"fild", "fisttp", "fist", "fistp", "fbld", "fistp", "fbstp", "fistp"},      // DF
};

// The register forms are runs of eight, one run per name, and a handful of singles.
// The runs are stated as a base byte and a name; the low three bits of the ModRM byte
// are then the stack register, which is why fadd st(0),st(1) and fadd st(0),st(2)
// differ only in that field.
typedef struct {
    uint8_t esc;
    uint8_t base; // the first byte of the run, low three bits zero
    uint8_t count;
    const char *name;
    uint8_t shape; // how the stack register reads: see the shapes below
    uint8_t last;  // the last byte of a run whose names change inside it
} x87_run_t;

// The shapes, in the order a reader says them.
#define X87_NONE 0u   // no operand at all
#define X87_ST 1u     // st(i)
#define X87_ST0_ST 2u // st(0), st(i)
#define X87_ST_ST0 3u // st(i), st(0)

static const x87_run_t kX87Runs[] = {
    {0xD8, 0xC0, 8, "fadd", X87_ST0_ST, 0},     {0xD8, 0xC8, 8, "fmul", X87_ST0_ST, 0},
    {0xD8, 0xD0, 16, "fcom", X87_ST0_ST, 0}, // D0..DF: fcom and fcomp
    {0xD8, 0xE0, 8, "fsub", X87_ST0_ST, 0},     {0xD8, 0xE8, 8, "fsubr", X87_ST0_ST, 0},
    {0xD8, 0xF0, 8, "fdiv", X87_ST0_ST, 0},     {0xD8, 0xF8, 8, "fdivr", X87_ST0_ST, 0},
    {0xDC, 0xC0, 8, "fadd", X87_ST_ST0, 0},     {0xDC, 0xC8, 8, "fmul", X87_ST_ST0, 0},
    {0xDC, 0xE0, 8, "fsubr", X87_ST_ST0, 0},    {0xDC, 0xE8, 8, "fsub", X87_ST_ST0, 0},
    {0xDC, 0xF0, 8, "fdivr", X87_ST_ST0, 0},    {0xDC, 0xF8, 8, "fdiv", X87_ST_ST0, 0},
    {0xD9, 0xC0, 8, "fld", X87_ST, 0},          {0xD9, 0xC8, 8, "fxch", X87_ST, 0},
    {0xDA, 0xC0, 8, "fcmovb", X87_ST0_ST, 0},   {0xDA, 0xC8, 8, "fcmove", X87_ST0_ST, 0},
    {0xDA, 0xD0, 8, "fcmovbe", X87_ST0_ST, 0},  {0xDA, 0xD8, 8, "fcmovu", X87_ST0_ST, 0},
    {0xDB, 0xC0, 8, "fcmovnb", X87_ST0_ST, 0},  {0xDB, 0xC8, 8, "fcmovne", X87_ST0_ST, 0},
    {0xDB, 0xD0, 8, "fcmovnbe", X87_ST0_ST, 0}, {0xDB, 0xD8, 8, "fcmovnu", X87_ST0_ST, 0},
    {0xDB, 0xE8, 8, "fucomi", X87_ST0_ST, 0},   {0xDB, 0xF0, 8, "fcomi", X87_ST0_ST, 0},
    {0xDD, 0xC0, 8, "ffree", X87_ST, 0},        {0xDD, 0xD0, 8, "fst", X87_ST, 0},
    {0xDD, 0xD8, 8, "fstp", X87_ST, 0},         {0xDD, 0xE0, 8, "fucom", X87_ST, 0},
    {0xDD, 0xE8, 8, "fucomp", X87_ST, 0},       {0xDE, 0xC0, 8, "faddp", X87_ST_ST0, 0},
    {0xDE, 0xC8, 8, "fmulp", X87_ST_ST0, 0},    {0xDE, 0xE0, 8, "fsubrp", X87_ST_ST0, 0},
    {0xDE, 0xE8, 8, "fsubp", X87_ST_ST0, 0},    {0xDE, 0xF0, 8, "fdivrp", X87_ST_ST0, 0},
    {0xDE, 0xF8, 8, "fdivp", X87_ST_ST0, 0},    {0xDF, 0xC0, 8, "ffreep", X87_ST, 0},
    {0xDF, 0xE8, 8, "fucomip", X87_ST0_ST, 0},  {0xDF, 0xF0, 8, "fcomip", X87_ST0_ST, 0},
};

// The register forms that are one opcode each. The numbering does not repeat between
// escapes, so they are written out: D9 E0 is fchs, and nothing about E0 says that.
typedef struct {
    uint8_t esc;
    uint8_t op;
    const char *name;
} x87_one_t;

static const x87_one_t kX87Singles[] = {
    {0xD9, 0xD0, "fnop"},    {0xD9, 0xE0, "fchs"},    {0xD9, 0xE1, "fabs"},
    {0xD9, 0xE4, "ftst"},    {0xD9, 0xE5, "fxam"},    {0xD9, 0xE8, "fld1"},
    {0xD9, 0xE9, "fldl2t"},  {0xD9, 0xEA, "fldl2e"},  {0xD9, 0xEB, "fldpi"},
    {0xD9, 0xEC, "fldlg2"},  {0xD9, 0xED, "fldln2"},  {0xD9, 0xEE, "fldz"},
    {0xD9, 0xF0, "f2xm1"},   {0xD9, 0xF1, "fyl2x"},   {0xD9, 0xF2, "fptan"},
    {0xD9, 0xF3, "fpatan"},  {0xD9, 0xF4, "fxtract"}, {0xD9, 0xF5, "fprem1"},
    {0xD9, 0xF6, "fdecstp"}, {0xD9, 0xF7, "fincstp"}, {0xD9, 0xF8, "fprem"},
    {0xD9, 0xF9, "fyl2xp1"}, {0xD9, 0xFA, "fsqrt"},   {0xD9, 0xFB, "fsincos"},
    {0xD9, 0xFC, "frndint"}, {0xD9, 0xFD, "fscale"},  {0xD9, 0xFE, "fsin"},
    {0xD9, 0xFF, "fcos"},    {0xDA, 0xE9, "fucompp"}, {0xDB, 0xE2, "fnclex"},
    {0xDB, 0xE3, "fninit"},  {0xDB, 0xE4, "fsetpm"},  {0xDE, 0xD9, "fcompp"},
    {0xDF, 0xE0, "fnstsw"},
};

// The run a register form belongs to, with the name a run whose two halves differ
// takes. D8 D0..DF is fcom then fcomp, which is the only run here that changes name
// inside itself.
static const x87_run_t *x87_run_find(uint8_t esc, uint8_t modrm) {
    for (size_t i = 0; i < sizeof(kX87Runs) / sizeof(kX87Runs[0]); i++) {
        const x87_run_t *r = &kX87Runs[i];
        if (r->esc != esc)
            continue;
        if (modrm >= r->base && modrm < r->base + r->count)
            return r;
    }
    return NULL;
}

const char *x64_x87_mnem(uint8_t esc, uint8_t modrm, bool mem, uint8_t *shape, uint8_t *st) {
    *shape = X87_NONE;
    *st = (uint8_t)(modrm & 7u);
    if (esc < 0xD8u || esc > 0xDFu)
        return NULL;
    if (mem)
        return kX87Mem[esc - 0xD8u][(modrm >> 3) & 7u];
    {
        const x87_run_t *r = x87_run_find(esc, modrm);
        if (r) {
            // D8 D0..D7 is fcom and D8 D8..DF is fcomp: one run of sixteen whose name
            // changes in the middle, which is why the count is stated as sixteen.
            if (esc == 0xD8u && r->base == 0xD0u && modrm >= 0xD8u)
                return "fcomp";
            *shape = r->shape;
            return r->name;
        }
    }
    for (size_t i = 0; i < sizeof(kX87Singles) / sizeof(kX87Singles[0]); i++) {
        if (kX87Singles[i].esc == esc && kX87Singles[i].op == modrm)
            return kX87Singles[i].name;
    }
    return NULL;
}

// The size of an x87 memory operand, in bytes, indexed by the escape and the reg
// field. It is not the instruction's operand size: the escape decides, and within an
// escape the operation does, so a table is the only honest way to say it. fld is four
// bytes in one escape, eight in another and ten in a third, and fild is two, four or
// eight by the same rule. A zero is an operand whose size no register can state, the
// environment and save areas.
static const uint8_t kX87MemW[8][8] = {
    {4, 4, 4, 4, 4, 4, 4, 4},    // D8 the single precision arithmetic
    {4, 4, 4, 4, 0, 2, 0, 2},    // D9 the loads, and the control word
    {4, 4, 4, 4, 4, 4, 4, 4},    // DA the thirty two bit integer arithmetic
    {4, 4, 4, 4, 10, 8, 10, 10}, // DB the conversions, including the ten byte
    {8, 8, 8, 8, 8, 8, 8, 8},    // DC the double precision arithmetic
    {8, 8, 8, 8, 0, 0, 0, 2},    // DD the double loads and the status word
    {2, 2, 2, 2, 2, 2, 2, 2},    // DE the sixteen bit integer arithmetic
    {2, 2, 2, 2, 10, 8, 10, 8},  // DF the remaining conversions
};

const char *x64_x87_mem_kw(const re_insn_t *in) {
    unsigned op = X64_ID_OP(in->insn_id);
    unsigned reg = ((unsigned)in->modrm >> 3) & 7u;
    switch (kX87MemW[op - 0xD8u][reg]) {
        case 2:
            return "word ptr ";
        case 4:
            return "dword ptr ";
        case 8:
            return "qword ptr ";
        case 10:
            return "tbyte ptr ";
        default:
            return "";
    }
}

// The x87 register forms, which name a stack register rather than a ModRM operand:
// fadd st(0), st(2) is two registers decided by the whole byte, not by a field.
void x64_x87_regs(re_strbuf_t *out, const re_insn_t *in) {
    unsigned op = X64_ID_OP(in->insn_id);
    uint8_t shape = 0;
    uint8_t st = 0;
    if (!x64_x87_mnem((uint8_t)op, in->modrm, false, &shape, &st))
        return;
    if (shape == X87_NONE)
        return;
    if (shape == X87_ST) {
        re_strbuf_appendf(out, " st(%u)", (unsigned)st);
        return;
    }
    if (shape == X87_ST0_ST)
        re_strbuf_appendf(out, " st(0), st(%u)", (unsigned)st);
    else
        re_strbuf_appendf(out, " st(%u), st(0)", (unsigned)st);
}
