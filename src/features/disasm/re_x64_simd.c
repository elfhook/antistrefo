// re_x64_simd.c - the mnemonics the opcode alone does not determine.
// Module: feature (C11).
// Owns: the prefix dependent SIMD names, the VEX maps, and the x87 tables.
// Depends: re_x64_priv.h. A name here is looked up, never composed from the opcode
//           number, so an encoding nobody has named reads as unnamed.
#include "features/disasm/re_x64_priv.h"

// One SIMD opcode's four names: no prefix, 0x66, 0xF3, 0xF2. The same byte is a
// different instruction under each, and the table in the opcode map can only hold
// one of them. A NULL means the prefix has no form of this opcode.
typedef struct {
    uint8_t op;
    const char *none;
    const char *pfx66;
    const char *pfx_f3;
    const char *pfx_f2;
} sse_name_t;

// 0F 10 through 0F 17: the moves, which are where the prefix decides between a
// scalar, a packed and an unaligned form.
static const sse_name_t kSseMove[] = {
    {0x10, "movups", "movupd", "movss", "movsd"},      {0x11, "movups", "movupd", "movss", "movsd"},
    {0x12, "movlps", "movlpd", "movsldup", "movddup"}, {0x13, "movlps", "movlpd", NULL, NULL},
    {0x14, "unpcklps", "unpcklpd", NULL, NULL},        {0x15, "unpckhps", "unpckhpd", NULL, NULL},
    {0x16, "movhps", "movhpd", "movshdup", NULL},      {0x17, "movhps", "movhpd", NULL, NULL},
};

// 0F 28 through 0F 2F: the aligned moves and the scalar conversions.
static const sse_name_t kSseCvt[] = {
    {0x28, "movaps", "movapd", NULL, NULL},
    {0x29, "movaps", "movapd", NULL, NULL},
    {0x2A, "cvtpi2ps", "cvtpi2pd", "cvtsi2ss", "cvtsi2sd"},
    {0x2B, "movntps", "movntpd", "movntss", "movntsd"},
    {0x2C, "cvttps2pi", "cvttpd2pi", "cvttss2si", "cvttsd2si"},
    {0x2D, "cvtps2pi", "cvtpd2pi", "cvtss2si", "cvtsd2si"},
    {0x2E, "ucomiss", "ucomisd", NULL, NULL},
    {0x2F, "comiss", "comisd", NULL, NULL},
};

// 0F 50 through 0F 5F: the sign masks and the arithmetic. This is the block a reader
// sees most often, and the prefix is the only thing that separates "addps" from
// "addsd".
static const sse_name_t kSseMath[] = {
    {0x50, "movmskps", "movmskpd", NULL, NULL},
    {0x51, "sqrtps", "sqrtpd", "sqrtss", "sqrtsd"},
    {0x52, "rsqrtps", NULL, "rsqrtss", NULL},
    {0x53, "rcpps", NULL, "rcpss", NULL},
    {0x54, "andps", "andpd", NULL, NULL},
    {0x55, "andnps", "andnpd", NULL, NULL},
    {0x56, "orps", "orpd", NULL, NULL},
    {0x57, "xorps", "xorpd", NULL, NULL},
    {0x58, "addps", "addpd", "addss", "addsd"},
    {0x59, "mulps", "mulpd", "mulss", "mulsd"},
    {0x5A, "cvtps2pd", "cvtpd2ps", "cvtss2sd", "cvtsd2ss"},
    {0x5B, "cvtdq2ps", "cvtps2dq", "cvttps2dq", NULL},
    {0x5C, "subps", "subpd", "subss", "subsd"},
    {0x5D, "minps", "minpd", "minss", "minsd"},
    {0x5E, "divps", "divpd", "divss", "divsd"},
    {0x5F, "maxps", "maxpd", "maxss", "maxsd"},
};

// 0F 60 through 0F 7F and C2 through C6: the integer and shuffle forms. Under 0x66 the
// same opcode works on xmm registers instead of the mmx ones, and under F3 or F2 it is
// a different instruction altogether, which is why the names are here and not in the
// opcode map.
static const sse_name_t kSseMisc[] = {
    // The bounds moves, whose four names are bndldx and bndstx plus the bndmov,
    // bndcl, bndcu, bndmk and bndcn forms the prefixes select.
    {0x1A, "bndldx", "bndmov", "bndcl", "bndcu"},
    {0x1B, "bndstx", "bndmov", "bndmk", "bndcn"},
    {0x60, "punpcklbw", "punpcklbw", NULL, NULL},
    {0x61, "punpcklwd", "punpcklwd", NULL, NULL},
    {0x62, "punpckldq", "punpckldq", NULL, NULL},
    {0x63, "packsswb", "packsswb", NULL, NULL},
    {0x64, "pcmpgtb", "pcmpgtb", NULL, NULL},
    {0x65, "pcmpgtw", "pcmpgtw", NULL, NULL},
    {0x66, "pcmpgtd", "pcmpgtd", NULL, NULL},
    {0x67, "packuswb", "packuswb", NULL, NULL},
    {0x68, "punpckhbw", "punpckhbw", NULL, NULL},
    {0x69, "punpckhwd", "punpckhwd", NULL, NULL},
    {0x6A, "punpckhdq", "punpckhdq", NULL, NULL},
    {0x6B, "packssdw", "packssdw", NULL, NULL},
    {0x6C, NULL, "punpcklqdq", NULL, NULL},
    {0x6D, NULL, "punpckhqdq", NULL, NULL},
    {0x6E, "movd", "movd", NULL, NULL},
    {0x6F, "movq", "movdqa", "movdqu", NULL},
    {0x70, "pshufw", "pshufd", "pshufhw", "pshuflw"},
    {0x74, "pcmpeqb", "pcmpeqb", NULL, NULL},
    {0x75, "pcmpeqw", "pcmpeqw", NULL, NULL},
    {0x76, "pcmpeqd", "pcmpeqd", NULL, NULL},
    {0x7C, NULL, "haddpd", NULL, "haddps"},
    {0x7D, NULL, "hsubpd", NULL, "hsubps"},
    {0x7E, "movd", "movd", "movq", NULL},
    {0x7F, "movq", "movdqa", "movdqu", NULL},
    {0xC2, "cmpps", "cmppd", "cmpss", "cmpsd"},
    {0xC3, "movnti", "movnti", NULL, NULL},
    {0xC4, "pinsrw", "pinsrw", NULL, NULL},
    {0xC5, "pextrw", "pextrw", NULL, NULL},
    {0xC6, "shufps", "shufpd", NULL, NULL},
    // The packed integer block above 0xC6, where the opcode map can only hold one
    // of the names. Half of these are mmx operations without a prefix and xmm ones
    // under 0x66, and the two conversions move between the two register files.
    {0xD0, NULL, "addsubpd", NULL, "addsubps"},
    {0xD6, "movq", "movq", "movq2dq", "movdq2q"},
    {0xE6, "cvtpd2pi", "cvttpd2dq", "cvtdq2pd", "cvtpd2dq"},
    {0xE7, "movntq", "movntdq", NULL, NULL},
    {0xF0, NULL, NULL, NULL, "lddqu"},
    {0xF7, "maskmovq", "maskmovdqu", NULL, NULL},
};

static const char *from4(const sse_name_t *t, uint8_t pfx) {
    switch (pfx) {
        case 0:
            return t->none;
        case 1:
            return t->pfx66;
        case 2:
            return t->pfx_f3;
        default:
            return t->pfx_f2;
    }
}

// The VEX maps. These carry almost every instruction the legacy maps do not, so the
// opcode is looked up in a sparse table and anything absent reads as unnamed rather
// than as a number with a shape around it.
typedef struct {
    uint8_t op;
    const char *name;
} vex_name_t;

static const vex_name_t kMap38[] = {
    {0x00, "pshufb"},
    {0x01, "phaddw"},
    {0x02, "phaddd"},
    {0x03, "phaddsw"},
    {0x04, "pmaddubsw"},
    {0x05, "phsubw"},
    {0x06, "phsubd"},
    {0x07, "phsubsw"},
    {0x08, "psignb"},
    {0x09, "psignw"},
    {0x0A, "psignd"},
    {0x0B, "pmulhrsw"},
    {0x0C, "permilps"},
    {0x0D, "permilpd"},
    {0x0E, "testps"},
    {0x0F, "testpd"},
    {0x10, "pblendvb"},
    {0x14, "blendvps"},
    {0x15, "blendvpd"},
    {0x17, "ptest"},
    {0x18, "broadcastss"},
    {0x19, "broadcastsd"},
    {0x1A, "broadcastf128"},
    {0x1C, "pabsb"},
    {0x1D, "pabsw"},
    {0x1E, "pabsd"},
    {0x20, "pmovsxbw"},
    {0x21, "pmovsxbd"},
    {0x22, "pmovsxbq"},
    {0x23, "pmovsxwd"},
    {0x24, "pmovsxwq"},
    {0x25, "pmovsxdq"},
    {0x28, "pmuldq"},
    {0x29, "pcmpeqq"},
    {0x2A, "movntdqa"},
    {0x2B, "packusdw"},
    {0x2C, "vmaskmovps"},
    {0x2D, "vmaskmovpd"},
    {0x2E, "vmaskmovps"},
    {0x2F, "vmaskmovpd"},
    {0x30, "pmovzxbw"},
    {0x31, "pmovzxbd"},
    {0x32, "pmovzxbq"},
    {0x33, "pmovzxwd"},
    {0x34, "pmovzxwq"},
    {0x35, "pmovzxdq"},
    {0x37, "pcmpgtq"},
    {0x38, "pminsb"},
    {0x39, "pminsd"},
    {0x3A, "pminuw"},
    {0x3B, "pminud"},
    {0x3C, "pmaxsb"},
    {0x3D, "pmaxsd"},
    {0x3E, "pmaxuw"},
    {0x3F, "pmaxud"},
    {0x40, "pmulld"},
    {0x41, "phminposuw"},
    {0x45, "psrlvd"},
    {0x46, "psrlvq"},
    {0x47, "psravd"},
    {0x58, "pbroadcastd"},
    {0x59, "pbroadcastq"},
    {0x5A, "broadcasti128"},
    {0x78, "pbroadcastb"},
    {0x79, "pbroadcastw"},
    {0x8C, "pmaskmovd"},
    {0x8E, "pmaskmovq"},
    {0x90, "gatherd"},
    {0x91, "gatherq"},
    // The SHA extensions carry no implicit prefix: the shared xmm0 is the reason the
    // map is one opcode per instruction rather than four names per opcode.
    {0xC8, "sha1nexte"},
    {0xC9, "sha1msg1"},
    {0xCA, "sha1msg2"},
    {0xCB, "sha256rnds2"},
    {0xCC, "sha256msg1"},
    {0xCD, "sha256msg2"},
    {0xDB, "aesimc"},
    {0xDC, "aesenc"},
    {0xDD, "aesenclast"},
    {0xDE, "aesdec"},
    {0xDF, "aesdeclast"},
};

static const vex_name_t kMap3A[] = {
    {0x00, "permq"},      {0x01, "permpd"},      {0x02, "pblendd"},    {0x04, "permilps"},
    {0x05, "permilpd"},   {0x06, "perm2f128"},   {0x08, "roundps"},    {0x09, "roundpd"},
    {0x0A, "roundss"},    {0x0B, "roundsd"},     {0x0C, "blendps"},    {0x0D, "blendpd"},
    {0x0E, "pblendw"},    {0x0F, "palignr"},     {0x14, "pextrb"},     {0x15, "pextrw"},
    {0x16, "pextrd"},     {0x17, "extractps"},   {0x18, "insertf128"}, {0x19, "extractf128"},
    {0x1D, "cvtps2ph"},   {0x20, "pinsrb"},      {0x21, "insertps"},   {0x22, "pinsrd"},
    {0x38, "inserti128"}, {0x39, "extracti128"}, {0x40, "dpps"},       {0x41, "dppd"},
    {0x42, "mpsadbw"},    {0x44, "pclmulqdq"},   {0x46, "perm2i128"},  {0x4A, "blendvps"},
    {0x4B, "blendvpd"},   {0x4C, "pblendvb"},    {0x60, "pcmpestrm"},  {0x61, "pcmpestri"},
    {0x62, "pcmpistrm"},  {0x63, "pcmpistri"},   {0xCC, "sha1rnds4"},  {0xDF, "aeskeygenassist"},
};

// The 0F38 opcodes whose name the prefix decides. Most of the map is one name per
// byte, but the byte swapping moves and the carry chains share their opcodes with
// each other, which is the same shape the 0F map's tables have.
static const sse_name_t kMap38Pfx[] = {
    {0xF0, "movbe", "movbe", NULL, "crc32"},
    {0xF1, "movbe", "movbe", NULL, "crc32"},
    {0xF6, NULL, "adcx", "adox", NULL},
};

static const char *sparse(const vex_name_t *t, size_t n, unsigned op) {
    for (size_t i = 0; i < n; i++) {
        if (t[i].op == op)
            return t[i].name;
    }
    return NULL;
}

// The group opcodes of the 0F map. Each one takes its mnemonic from the reg field,
// and some from the mod field as well: 0F 01 /7 is invlpg in memory and rdtscp in a
// register, and one name for both would be wrong for one of them.
typedef struct {
    uint8_t reg;
    const char *name;
} grp_name_t;

static const grp_name_t kGrp6[] = {{0, "sldt"}, {1, "str"},  {2, "lldt"},
                                   {3, "ltr"},  {4, "verr"}, {5, "verw"}};
static const grp_name_t kGrp7[] = {{0, "sgdt"}, {1, "sidt"}, {2, "lgdt"},  {3, "lidt"},
                                   {4, "smsw"}, {6, "lmsw"}, {7, "invlpg"}};
// The same opcode with a register operand is a different instruction set entirely:
// the virtual machine extensions, the monitor instructions and the user mode ones.
static const grp_name_t kGrp7Reg[] = {
    {0xC1, "vmcall"},  {0xC2, "vmlaunch"}, {0xC3, "vmresume"}, {0xC4, "vmxoff"},
    {0xC8, "monitor"}, {0xC9, "mwait"},    {0xD0, "xgetbv"},   {0xD1, "xsetbv"},
    {0xD8, "vmrun"},   {0xD9, "vmmcall"},  {0xDA, "vmload"},   {0xDB, "vmsave"},
    {0xDC, "stgi"},    {0xDD, "clgi"},     {0xDE, "skinit"},   {0xDF, "invlpga"},
    {0xF8, "swapgs"},  {0xF9, "rdtscp"},   {0xFA, "monitorx"}, {0xFB, "mwaitx"},
};
// Only the register forms: the memory forms of the same opcode are the compare and
// exchange, the state saves and the virtual machine roots, and none of them has a
// register form at all. Keeping both in one table named a register cmpxchg8b.
static const grp_name_t kGrp9[] = {{6, "rdrand"}, {7, "rdseed"}};
static const grp_name_t kGrp9Mem[] = {{1, "cmpxchg8b"}, {3, "xrstors"}, {4, "xsavec"},
                                      {5, "xsaves"},    {6, "vmptrld"}, {7, "vmptrst"}};
// 0F BA is the bit test group, and 0F 0D is the prefetch hint group: both take their
// name from the reg field and have no other place to hold it.
static const grp_name_t kGrp8[] = {{4, "bt"}, {5, "bts"}, {6, "btr"}, {7, "btc"}};
static const grp_name_t kGrp0D[] = {{0, "prefetch"}, {1, "prefetchw"}, {2, "prefetchwt1"}};
static const grp_name_t kGrp1C[] = {{0, "cldemote"}};
static const grp_name_t kGrp15[] = {{0, "fxsave"}, {1, "fxrstor"}, {2, "ldmxcsr"},  {3, "stmxcsr"},
                                    {4, "xsave"},  {5, "xrstor"},  {6, "xsaveopt"}, {7, "clflush"}};
static const grp_name_t kGrp15Reg[] = {{5, "lfence"}, {6, "mfence"}, {7, "sfence"}};
static const grp_name_t kGrp18[] = {
    {0, "prefetchnta"}, {1, "prefetcht0"}, {2, "prefetcht1"}, {3, "prefetcht2"}};
// The segment status forms: the same reg fields as the descriptor loads, but with a
// register operand rather than a memory one.
static const grp_name_t kGrp7RegAlt[] = {{4, "smsw"}, {6, "lmsw"}};

// The shift groups 12, 13 and 14 share one layout with the vector width differing
// between them: 0F 71 shifts words, 0F 72 dwords and 0F 73 qwords.
static const grp_name_t kGrp12[] = {{2, "psrlw"}, {4, "psraw"}, {6, "psllw"}};
static const grp_name_t kGrp13[] = {{2, "psrld"}, {4, "psrad"}, {6, "pslld"}};
static const grp_name_t kGrp14[] = {{2, "psrlq"}, {3, "psrldq"}, {6, "psllq"}, {7, "pslldq"}};

static const grp_name_t *grp_pick(const grp_name_t *t, size_t n, unsigned key) {
    for (size_t i = 0; i < n; i++) {
        if (t[i].reg == key)
            return &t[i];
    }
    return NULL;
}

// The 3DNow opcodes. The opcode byte is 0F 0F for all of them and the trailing
// immediate is what selects the operation, which is the one place in x86 where the
// meaning of an instruction is in the byte after its ModRM.
static const grp_name_t k3DNow[] = {
    {0x0C, "pi2fw"},    {0x0D, "pi2fd"},   {0x1C, "pf2iw"},   {0x1D, "pf2id"},   {0x8A, "pfnacc"},
    {0x8E, "pfpnacc"},  {0x90, "pfcmpge"}, {0x94, "pfmin"},   {0x96, "pfrcp"},   {0x97, "pfrsqrt"},
    {0x9A, "pfsub"},    {0x9E, "pfadd"},   {0xA0, "pfcmpgt"}, {0xA4, "pfmax"},   {0xA6, "pfrcpit1"},
    {0xA7, "pfrsqit1"}, {0xAA, "pfsubr"},  {0xAE, "pfacc"},   {0xB0, "pfcmpeq"}, {0xB4, "pfmul"},
    {0xB6, "pfrcpit2"}, {0xB7, "pmulhrw"}, {0xBB, "pswapd"},  {0xBF, "pavgusb"},
};

// The bytes a prefix moves to a different instruction. A cache line writeback shares
// its byte with a state save, the wait and monitor forms share theirs with a fence,
// and the virtual machine roots share theirs with a state load, so the prefix is the
// only thing that tells them apart. *handled reports that this function answered, so
// that a NULL here means no name rather than a fallback to the unprefixed table.
static const char *grp0f_prefixed(unsigned op, unsigned reg, bool mem, uint8_t pfx, bool *handled) {
    *handled = false;
    if (op == 0xAEu && reg == 6u && pfx == 1u) {
        *handled = true;
        return mem ? "clwb" : "tpause";
    }
    if (op == 0xAEu && reg == 7u && pfx == 1u) {
        *handled = true;
        return mem ? "clflushopt" : NULL;
    }
    if (op == 0xAEu && reg == 6u && pfx == 2u) {
        *handled = true;
        return mem ? NULL : "umonitor";
    }
    if (op == 0xAEu && reg == 6u && pfx == 3u) {
        *handled = true;
        return mem ? NULL : "umwait";
    }
    if (op == 0xC7u && pfx == 1u && reg == 6u) {
        *handled = true;
        return mem ? "vmclear" : NULL;
    }
    if (op == 0xC7u && pfx == 2u && reg == 6u) {
        *handled = true;
        return mem ? "vmxon" : "senduipi";
    }
    if (op == 0xC7u && pfx == 2u && reg == 7u) {
        *handled = true;
        return mem ? NULL : "rdpid";
    }
    if (op == 0xAEu && pfx == 2u && !mem && reg <= 3u) {
        static const char *const kFsgs[4] = {"rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase"};
        *handled = true;
        return kFsgs[reg];
    }
    return NULL;
}

const char *x64_grp0f_mnem(unsigned op, unsigned modrm, int64_t imm, bool mem, uint8_t pfx) {
    unsigned reg = (modrm >> 3) & 7u;
    const grp_name_t *g = NULL;
    bool handled = false;
    const char *alt = grp0f_prefixed(op, reg, mem, pfx, &handled);
    if (handled)
        return alt;
    switch (op) {
        case 0x00:
            g = grp_pick(kGrp6, sizeof(kGrp6) / sizeof(kGrp6[0]), reg);
            break;
        case 0x01:
            if (mem) {
                g = grp_pick(kGrp7, sizeof(kGrp7) / sizeof(kGrp7[0]), reg);
                break;
            }
            g = grp_pick(kGrp7Reg, sizeof(kGrp7Reg) / sizeof(kGrp7Reg[0]), modrm);
            if (!g)
                g = grp_pick(kGrp7RegAlt, sizeof(kGrp7RegAlt) / sizeof(kGrp7RegAlt[0]), reg);
            break;
        case 0x0D:
            // The hint group is memory only, so with a register operand the byte has
            // no name at all rather than naming a prefetch of a register.
            if (!mem)
                return NULL;
            g = grp_pick(kGrp0D, sizeof(kGrp0D) / sizeof(kGrp0D[0]), reg);
            break;
        case 0x1C:
            // The cache line demote names a memory address too, and only in the form
            // that carries no prefix at all.
            if (pfx != 0u || !mem)
                return NULL;
            g = grp_pick(kGrp1C, sizeof(kGrp1C) / sizeof(kGrp1C[0]), reg);
            break;
        case 0x0F: {
            // The selector is an unsigned byte the decoder sign extended, so it is
            // masked back to the eight bits the encoding carries before lookup.
            const grp_name_t *d =
                grp_pick(k3DNow, sizeof(k3DNow) / sizeof(k3DNow[0]), (unsigned)imm & 0xFFu);
            return d ? d->name : NULL;
        }
        case 0xBA:
            g = grp_pick(kGrp8, sizeof(kGrp8) / sizeof(kGrp8[0]), reg);
            break;
        case 0xC7:
            // The compare and exchange, the state saves and the virtual machine
            // roots are the memory forms; rdrand and rdseed are the register ones.
            g = mem ? grp_pick(kGrp9Mem, sizeof(kGrp9Mem) / sizeof(kGrp9Mem[0]), reg)
                    : grp_pick(kGrp9, sizeof(kGrp9) / sizeof(kGrp9[0]), reg);
            break;
        case 0x71:
            g = grp_pick(kGrp12, sizeof(kGrp12) / sizeof(kGrp12[0]), reg);
            break;
        case 0x72:
            g = grp_pick(kGrp13, sizeof(kGrp13) / sizeof(kGrp13[0]), reg);
            break;
        case 0x73:
            g = grp_pick(kGrp14, sizeof(kGrp14) / sizeof(kGrp14[0]), reg);
            break;
        case 0xAE:
            g = mem ? grp_pick(kGrp15, sizeof(kGrp15) / sizeof(kGrp15[0]), reg)
                    : grp_pick(kGrp15Reg, sizeof(kGrp15Reg) / sizeof(kGrp15Reg[0]), reg);
            break;
        case 0x18:
            // PREFETCHh names a memory address and nothing else. The byte with a
            // register operand is reserved, and naming a prefetch of a register
            // invents an operand the instruction cannot have.
            if (!mem)
                return NULL;
            g = grp_pick(kGrp18, sizeof(kGrp18) / sizeof(kGrp18[0]), reg);
            break;
        default:
            return NULL;
    }
    return g ? g->name : NULL;
}

// The entry for an opcode, across all four blocks. One lookup serves both the name
// and the question of whether the prefix decides it, so the two can never disagree
// about which opcodes are prefix sensitive.
static const sse_name_t *sse_find(unsigned op) {
    static const sse_name_t *const sets[] = {kSseMove, kSseCvt, kSseMath, kSseMisc};
    static const size_t counts[] = {
        sizeof(kSseMove) / sizeof(kSseMove[0]), sizeof(kSseCvt) / sizeof(kSseCvt[0]),
        sizeof(kSseMath) / sizeof(kSseMath[0]), sizeof(kSseMisc) / sizeof(kSseMisc[0])};
    for (size_t s = 0; s < 4; s++) {
        for (size_t i = 0; i < counts[s]; i++) {
            if (sets[s][i].op == op)
                return &sets[s][i];
        }
    }
    return NULL;
}

static const sse_name_t *pfx_find(const sse_name_t *t, size_t n, unsigned op) {
    for (size_t i = 0; i < n; i++) {
        if (t[i].op == op)
            return &t[i];
    }
    return NULL;
}

const char *x64_simd_mnem(uint8_t map, unsigned op, uint8_t pfx) {
    if (map == 1) {
        const sse_name_t *e = sse_find(op);
        return e ? from4(e, pfx) : NULL; // a NULL here means the prefix has no form
    }
    if (map == 2) {
        const sse_name_t *e = pfx_find(kMap38Pfx, sizeof(kMap38Pfx) / sizeof(kMap38Pfx[0]), op);
        return e ? from4(e, pfx) : sparse(kMap38, sizeof(kMap38) / sizeof(kMap38[0]), op);
    }
    if (map == 3)
        return sparse(kMap3A, sizeof(kMap3A) / sizeof(kMap3A[0]), op);
    return NULL;
}

bool x64_simd_known(uint8_t map, unsigned op) {
    if (map == 1)
        return sse_find(op) != NULL;
    if (map == 2)
        return pfx_find(kMap38Pfx, sizeof(kMap38Pfx) / sizeof(kMap38Pfx[0]), op) != NULL ||
               sparse(kMap38, sizeof(kMap38) / sizeof(kMap38[0]), op) != NULL;
    if (map == 3)
        return sparse(kMap3A, sizeof(kMap3A) / sizeof(kMap3A[0]), op) != NULL;
    return false;
}
