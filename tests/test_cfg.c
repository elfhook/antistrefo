// test_cfg.c - the control flow graph of a hand assembled function.
// Module: test (C11).
// Owns: block partitioning, terminator classification and the edge list.
// Depends: re_core through the public headers, never a private one, so the graph is
//           built by the same calls the cfg command makes.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/dec/re_cfg.h"
#include "features/dec/re_dc_walk.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

int re_test_count = 0;
int re_test_fail = 0;

#define IMAGE_BASE 0x180000000ull
#define TEXT_RVA 0x1000u
#define HDRS 0x200u
#define OPT_SIZE 0xF0u

// A four block function chosen so every edge kind is unambiguous:
//
//   1000  cmp rax, 1
//   1004  je  0x100D            taken -> block 2, fall -> block 1
//   1006  mov eax, 1
//   100B  jmp 0x1013            taken -> block 3
//   100D  mov eax, 2
//   1012  ret
//   1013  ret
//
// Under the bug this suite exists for, only the first block was decoded and the
// graph came back as one block, so "more than one block" is the load bearing check.
static const uint8_t kCode[] = {
    0x48, 0x83, 0xf8, 0x01,       // 1000 cmp rax,1
    0x74, 0x07,                   // 1004 je +7 -> 100D
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1006 mov eax,1
    0xeb, 0x06,                   // 100B jmp +6 -> 1013
    0xb8, 0x02, 0x00, 0x00, 0x00, // 100D mov eax,2
    0xc3,                         // 1012 ret
    0xc3,                         // 1013 ret
};

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

// The smallest PE the parser accepts: a DOS stub, a COFF header, a PE32+ optional
// header with sixteen empty data directories, and one executable section. Every
// field the parser reads is written here, and nothing else, so a parser change that
// starts requiring a new field shows up as a failing test rather than as a silently
// different fixture.
static void build_pe(uint8_t *img) {
    memset(img, 0, HDRS);
    put16(img, 0x5A4D);             // MZ
    put32(img + 0x3C, 0x40);        // e_lfanew
    put32(img + 0x40, 0x00004550u); // PE\0\0
    uint8_t *coff = img + 0x44;
    put16(coff + 0, 0x8664);    // machine x64
    put16(coff + 2, 1);         // one section
    put16(coff + 16, OPT_SIZE); // SizeOfOptionalHeader
    put16(coff + 18, 0x0022);   // executable, large address aware
    uint8_t *opt = coff + 20;
    put16(opt, 0x20B);             // PE32+
    put32(opt + 16, TEXT_RVA);     // AddressOfEntryPoint
    put64(opt + 24, IMAGE_BASE);   // ImageBase
    put32(opt + 56, TEXT_RVA * 2); // SizeOfImage
    put16(opt + 68, 1);            // subsystem native
    put32(opt + 108, 16);          // NumberOfRvaAndSizes
    uint8_t *sec = img + 0x148;    // lfanew + 4 + 20 + SizeOfOptionalHeader
    memcpy(sec, ".text", 5);
    put32(sec + 8, (uint32_t)sizeof(kCode));  // VirtualSize
    put32(sec + 12, TEXT_RVA);                // VirtualAddress
    put32(sec + 16, (uint32_t)sizeof(kCode)); // SizeOfRawData
    put32(sec + 20, HDRS);                    // PointerToRawData
    put32(sec + 36, 0x60000020u);             // code, execute, read
    memcpy(img + HDRS, kCode, sizeof(kCode));
}

// The terminator of block i, or RE_CFG_TERM_UNKNOWN when there is no such block.
static uint8_t term_of(const re_cfg_t *g, size_t i) {
    if (i >= RE_VEC_LEN(&g->blocks))
        return RE_CFG_TERM_UNKNOWN;
    return RE_VEC_AT(&g->blocks, re_cfg_block_t, i).term;
}

// The destinations leaving block i, as edge kinds in order.
static size_t succ_kinds(const re_cfg_t *g, size_t from, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
        const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
        if (e->from == from && n < cap)
            out[n++] = e->kind;
    }
    return n;
}

// Whether block from reaches block to by the given kind.
static bool reaches(const re_cfg_t *g, size_t from, int32_t to, uint8_t kind) {
    for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
        const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
        if (e->from == from && e->to == to && e->kind == kind)
            return true;
    }
    return false;
}

// The block partitioning and the edges. Every expectation here is derived from the
// hand assembled fixture above, so a failure names the edge that changed rather than
// just a count that moved.
static void check_graph(re_code_t *code, const re_func_t *f, re_arena_t *a) {
    re_cfg_t g;
    uint8_t kinds[4];
    RE_CHECK(re_cfg_build(code, f, &g, a));
    RE_CHECK_FITS(g.blocks, 4);
    RE_CHECK(!g.truncated);
    RE_CHECK_EQ_U(term_of(&g, 0), RE_CFG_TERM_COND);
    RE_CHECK_EQ_U(term_of(&g, 1), RE_CFG_TERM_JUMP);
    RE_CHECK_EQ_U(term_of(&g, 2), RE_CFG_TERM_RET);
    RE_CHECK_EQ_U(term_of(&g, 3), RE_CFG_TERM_RET);
    RE_CHECK(reaches(&g, 0, 2, RE_CFG_EDGE_TAKEN));
    RE_CHECK(reaches(&g, 0, 1, RE_CFG_EDGE_FALL));
    RE_CHECK(reaches(&g, 1, 3, RE_CFG_EDGE_TAKEN));
    RE_CHECK_EQ_U(succ_kinds(&g, 2, kinds, 4), 0);
    RE_CHECK_EQ_U(succ_kinds(&g, 3, kinds, 4), 0);
    RE_CHECK_EQ_U(succ_kinds(&g, 0, kinds, 4), 2);
    RE_CHECK_EQ_U(g.n_unknown, 0);
    RE_CHECK_EQ_U(g.n_unresolved, 0);
}

// The walk on its own, because the decompiler reads the same structure and a missing
// label there is what makes it print a bare address instead of an L number.
static void check_walk(re_code_t *code, const re_func_t *f, re_arena_t *a) {
    re_dc_walk_t w = {0};
    re_dc_walk(code, f, &w, a);
    RE_CHECK_FITS(w.labels, 4);
    RE_CHECK(re_dc_label_of(&w, f->va) != 0);
    RE_CHECK(re_dc_label_of(&w, f->va + 6) != 0);
    RE_CHECK(re_dc_label_of(&w, f->va + 13) != 0);
    RE_CHECK(re_dc_label_of(&w, f->va + 19) != 0);
    RE_CHECK_EQ_U(re_dc_label_of(&w, f->va + 1), 0);
}

int main(void) {
    uint8_t img[HDRS + sizeof(kCode)];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_arena_init(&a, 65536);
    build_pe(img);

    re_span_t span = {img, sizeof(img)};
    re_pe_parse(span, &a, &pe);
    RE_CHECK(pe.valid);
    RE_CHECK_EQ_HEX(pe.image_base, IMAGE_BASE);
    RE_CHECK_EQ_U(pe.n_sec_field, 1);
    RE_CHECK(pe.pe32plus);

    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_func_scan(&code, &a, &scan);
    // The scanner may legitimately read the trailing "jmp" as a tail call and seed
    // the ret it points at as its own function, so only the count is asserted here.
    // What this suite is about is the graph, and that needs an extent covering the
    // whole fixture, so the function under test is stated explicitly rather than
    // taken from whatever extent the scan happened to record.
    RE_CHECK(RE_VEC_LEN(&scan.funcs) >= 1);

    re_func_t f;
    memset(&f, 0, sizeof(f));
    f.va = IMAGE_BASE + TEXT_RVA;
    f.rva = TEXT_RVA;
    f.size = (uint32_t)sizeof(kCode);
    f.flags = RE_FUNC_ENTRY | RE_FUNC_RET;

    // The regression this suite was written for: a function with four blocks and a
    // loop-free diamond must not collapse to one.
    check_graph(&code, &f, &a);
    check_walk(&code, &f, &a);
    re_arena_free(&a);
    return re_test_report("cfg");
}
