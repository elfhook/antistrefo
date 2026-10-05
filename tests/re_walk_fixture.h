// re_walk_fixture.h - one hand built PE where every recovery case has a function.
// Module: test (C11).
// Owns: the layout of an image whose bodies need resync, overlap and truncation.
// Depends: re_pe through its public header. Static inline throughout, so two
//           translation units may include it without a second definition.
//
// The layout, all RVAs in .text:
//
//   1000 AlphaFunc   push rbp; mov rax,[rip+0x20]; three bytes that decode to
//                    nothing; ret          -> the walk must skip three bytes
//   1020 GammaFunc   test eax,eax; je 1032; ret
//                    -> 1032 is inside DeltaFunc's first instruction, which is
//                       what an overlapping body looks like, and the earlier
//                       walk owns those bytes
//   1030 (entry)     sub rsp,0x20; ret
//   1040 DeltaFunc   4200 nops; ret        -> past the instruction ceiling
//   10A9 EpsilonFunc sub rsp,8; ud2        -> no way back to its caller
//   10AF ZetaFunc    cmp rax,1; ret        -> named by nothing; only the code
//                    pointer in .rdata reaches it
//
// 1060 is not used, so the offsets are stated rather than derived: a fixture whose
// addresses move when a body grows is a fixture that silently stops testing what
// the comment above it says it tests.
#pragma once

#include <stdint.h>
#include <string.h>

#include "features/pe/re_pe.h"

#define WALK_BASE 0x140000000ull
#define WALK_HDRS 0x200u
#define WALK_TEXT_RVA 0x1000u
// The data sections start above the end of .text, which is a long section here
// because of the instruction ceiling fixture. An overlapping RVA makes a lookup
// find .text first and read instructions as an export directory, which looks
// exactly like a parser that found nothing.
#define WALK_EDATA_RVA 0x3000u
#define WALK_EDATA_SIZE 0x140u
#define WALK_UNWIND_AT 0xD0u // clear of the export arrays, which end at 0x50
#define WALK_RDATA_RVA 0x4000u
#define WALK_RDATA_SIZE 8u
#define WALK_OPT_SIZE 0xF0u

#define WALK_FN_A 0x1000u
#define WALK_FN_A_END 0x100Cu
#define WALK_FN_B 0x1020u
#define WALK_FN_B_END 0x1025u
#define WALK_FN_C 0x1030u
#define WALK_FN_C_END 0x1035u
#define WALK_FN_TRUNC 0x1040u
#define WALK_TRUNC_NOPS 4200u
#define WALK_FN_TRUNC_END (WALK_FN_TRUNC + WALK_TRUNC_NOPS + 1u)
#define WALK_FN_HALT WALK_FN_TRUNC_END       // 0x10A9
#define WALK_FN_HALT_END (WALK_FN_HALT + 6u) // 0x10AF
#define WALK_FN_PTR WALK_FN_HALT_END         // 0x10AF
#define WALK_FN_PTR_END (WALK_FN_PTR + 5u)   // 0x10B4
#define WALK_CODE_BYTES (WALK_FN_PTR_END - WALK_TEXT_RVA)

#define WALK_IMG_BYTES (WALK_HDRS + WALK_CODE_BYTES + WALK_EDATA_SIZE + WALK_RDATA_SIZE)

static inline void walk_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void walk_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void walk_put64(uint8_t *p, uint64_t v) {
    walk_put32(p, (uint32_t)v);
    walk_put32(p + 4, (uint32_t)(v >> 32));
}

static inline void walk_putn(uint8_t *p, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        p[i] = b[i];
}

// The code section. The nop run is written by a loop rather than listed, because
// four thousand two hundred bytes of literal table would bury the six bytes of
// each function that the fixture is actually about.
static inline void walk_build_code(uint8_t *code) {
    static const uint8_t fn_a[] = {0x55, 0x48, 0x8b, 0x05, 0x20, 0x00,
                                   0x00, 0x00, 0x06, 0x0e, 0x16, 0xc3};
    static const uint8_t fn_b[] = {0x85, 0xc0, 0x74, 0x0e, 0xc3};
    static const uint8_t fn_c[] = {0x48, 0x83, 0xec, 0x20, 0xc3};
    static const uint8_t fn_halt[] = {0x48, 0x83, 0xec, 0x08, 0x0f, 0x0b};
    static const uint8_t fn_ptr[] = {0x48, 0x83, 0xf8, 0x01, 0xc3};
    memset(code, 0x90, WALK_CODE_BYTES); // nop padding between the bodies
    walk_putn(code + (WALK_FN_A - WALK_TEXT_RVA), fn_a, sizeof(fn_a));
    walk_putn(code + (WALK_FN_B - WALK_TEXT_RVA), fn_b, sizeof(fn_b));
    walk_putn(code + (WALK_FN_C - WALK_TEXT_RVA), fn_c, sizeof(fn_c));
    memset(code + (WALK_FN_TRUNC - WALK_TEXT_RVA), 0x90, WALK_TRUNC_NOPS);
    code[(WALK_FN_TRUNC - WALK_TEXT_RVA) + WALK_TRUNC_NOPS] = 0xc3;
    walk_putn(code + (WALK_FN_HALT - WALK_TEXT_RVA), fn_halt, sizeof(fn_halt));
    walk_putn(code + (WALK_FN_PTR - WALK_TEXT_RVA), fn_ptr, sizeof(fn_ptr));
}

// The export directory: the entry point is GammaFunc's target, and one function is
// left out of every table so that only the data pointer reaches it.
static inline void walk_build_exports(uint8_t *ed) {
    static const char *const names[4] = {"AlphaFunc", "GammaFunc", "DeltaFunc", "EpsilonFunc"};
    static const uint32_t rvas[4] = {WALK_FN_A, WALK_FN_B, WALK_FN_TRUNC, WALK_FN_HALT};
    walk_put32(ed + 12, WALK_EDATA_RVA + 0x80); // module name
    walk_put32(ed + 16, 1);                     // ordinal base
    walk_put32(ed + 20, 4);
    walk_put32(ed + 24, 4);
    walk_put32(ed + 28, WALK_EDATA_RVA + 0x28); // AddressOfFunctions
    walk_put32(ed + 32, WALK_EDATA_RVA + 0x38); // AddressOfNames
    walk_put32(ed + 36, WALK_EDATA_RVA + 0x48); // AddressOfNameOrdinals
    size_t str = 0x80;
    walk_putn(ed + str, (const uint8_t *)"walkmod.dll", 12);
    str += 12;
    for (size_t i = 0; i < 4; i++) {
        walk_put32(ed + 0x28 + i * 4, rvas[i]);
        walk_put32(ed + 0x38 + i * 4, WALK_EDATA_RVA + (uint32_t)str);
        walk_put16(ed + 0x48 + i * 2, (uint16_t)i);
        size_t len = 0;
        while (names[i][len])
            len++;
        walk_putn(ed + str, (const uint8_t *)names[i], len + 1);
        str += len + 1;
    }
}

// The exception table, one entry per function including the one that is past the
// instruction ceiling. A walk that has a declared end and still runs past it is
// the case this table exists to prevent, and DeltaFunc is where it would show.
static inline void walk_build_unwind(uint8_t *ed, uint32_t at) {
    static const uint32_t begin[5] = {WALK_FN_A, WALK_FN_B, WALK_FN_C, WALK_FN_TRUNC, WALK_FN_HALT};
    static const uint32_t end[5] = {WALK_FN_A_END, WALK_FN_B_END, WALK_FN_C_END, WALK_FN_TRUNC_END,
                                    WALK_FN_HALT_END};
    for (size_t i = 0; i < 5; i++) {
        walk_put32(ed + at + i * 12 + 0, begin[i]);
        walk_put32(ed + at + i * 12 + 4, end[i]);
        walk_put32(ed + at + i * 12 + 8, WALK_EDATA_RVA + 0x110); // shared unwind info
    }
}

// The whole image: headers, .text, .edata and a .rdata holding one absolute code
// pointer to the function nothing else names.
static inline void walk_build_pe(uint8_t *img) {
    memset(img, 0, WALK_IMG_BYTES);
    walk_put16(img, 0x5A4D);
    walk_put32(img + 0x3C, 0x40);
    walk_put32(img + 0x40, 0x00004550u);
    uint8_t *coff = img + 0x44;
    walk_put16(coff + 0, 0x8664);
    walk_put16(coff + 2, 3); // three sections
    walk_put16(coff + 16, WALK_OPT_SIZE);
    walk_put16(coff + 18, 0x0022);
    uint8_t *opt = coff + 20;
    walk_put16(opt, 0x20B);
    walk_put32(opt + 16, WALK_FN_C);          // AddressOfEntryPoint
    walk_put64(opt + 24, WALK_BASE);          // ImageBase
    walk_put32(opt + 56, WALK_RDATA_RVA * 2); // SizeOfImage
    walk_put16(opt + 68, 1);                  // subsystem native
    walk_put32(opt + 108, 16);                // NumberOfRvaAndSizes
    walk_put32(opt + 112, WALK_EDATA_RVA);    // export directory
    walk_put32(opt + 116, WALK_EDATA_SIZE);
    // The exception directory is index 3, so at optional header offset 136.
    walk_put32(opt + 136, WALK_EDATA_RVA + WALK_UNWIND_AT);
    walk_put32(opt + 140, 5u * 12u);
    uint8_t *sec = img + 0x148;
    walk_putn(sec, (const uint8_t *)".text", 6);
    walk_put32(sec + 8, WALK_CODE_BYTES);
    walk_put32(sec + 12, WALK_TEXT_RVA);
    walk_put32(sec + 16, WALK_CODE_BYTES);
    walk_put32(sec + 20, WALK_HDRS);
    walk_put32(sec + 36, 0x60000020u); // code, execute, read
    walk_putn(sec + 40, (const uint8_t *)".edata", 7);
    walk_put32(sec + 48, WALK_EDATA_SIZE);
    walk_put32(sec + 52, WALK_EDATA_RVA);
    walk_put32(sec + 56, WALK_EDATA_SIZE);
    walk_put32(sec + 60, WALK_HDRS + WALK_CODE_BYTES);
    walk_put32(sec + 76, 0x40000040u);
    walk_putn(sec + 80, (const uint8_t *)".rdata", 7);
    walk_put32(sec + 88, WALK_RDATA_SIZE);
    walk_put32(sec + 92, WALK_RDATA_RVA);
    walk_put32(sec + 96, WALK_RDATA_SIZE);
    walk_put32(sec + 100, WALK_HDRS + WALK_CODE_BYTES + WALK_EDATA_SIZE);
    walk_put32(sec + 116, 0x40000040u);
    walk_build_code(img + WALK_HDRS);
    uint8_t *ed = img + WALK_HDRS + WALK_CODE_BYTES;
    walk_build_exports(ed);
    walk_build_unwind(ed, WALK_UNWIND_AT);
    walk_put64(img + WALK_HDRS + WALK_CODE_BYTES + WALK_EDATA_SIZE, WALK_BASE + WALK_FN_PTR);
}
