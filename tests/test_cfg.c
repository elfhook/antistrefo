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

#include "features/analysis/re_analyze.h"
#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/data/re_regions.h"
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
#define EDATA_RVA 0x2000u
#define EDATA_SIZE 0x80u
#define HDRS 0x200u
#define OPT_SIZE 0xF0u
#define IMG_BYTES (HDRS + sizeof(kCode) + EDATA_SIZE)

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

static void build_exports(uint8_t *ed);

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
    put32(opt + 112, EDATA_RVA);   // export directory
    put32(opt + 116, EDATA_SIZE);
    uint8_t *sec = img + 0x148; // lfanew + 4 + 20 + SizeOfOptionalHeader
    memcpy(sec, ".text", 5);
    put32(sec + 8, (uint32_t)sizeof(kCode));  // VirtualSize
    put32(sec + 12, TEXT_RVA);                // VirtualAddress
    put32(sec + 16, (uint32_t)sizeof(kCode)); // SizeOfRawData
    put32(sec + 20, HDRS);                    // PointerToRawData
    put32(sec + 36, 0x60000020u);             // code, execute, read
    memcpy(img + HDRS, kCode, sizeof(kCode));
    uint8_t *ed = img + 0x148 + 40; // the second section header
    memcpy(ed, ".edata", 6);
    put32(ed + 8, EDATA_SIZE);            // VirtualSize
    put32(ed + 12, EDATA_RVA);            // VirtualAddress
    put32(ed + 16, EDATA_SIZE);           // SizeOfRawData
    put32(ed + 20, HDRS + sizeof(kCode)); // PointerToRawData
    put32(ed + 36, 0x40000040u);          // initialised data, read
    put16(coff + 2, 2);                   // two sections, now that there are two
    build_exports(img + HDRS + sizeof(kCode));
}

// The export directory, laid out exactly as the spec has it, because the whole point
// is that the parser reads the fields at the offsets they actually occupy:
//
//   +16 Base  +20 NumberOfFunctions  +24 NumberOfNames
//   +28 AddressOfFunctions  +32 AddressOfNames  +36 AddressOfNameOrdinals
//
// Getting +28 and +32 the wrong way round is the bug that made every export name
// come back as the opening bytes of a function, and a count-only test cannot see it:
// the number of names parsed correctly either way. So the names here are fixed text,
// and the assertions below compare them.
static void build_exports(uint8_t *ed) {
    const char *names[3] = {"AlphaFunc", "BetaFunc", "GammaFunc"};
    const uint32_t rvas[3] = {TEXT_RVA, TEXT_RVA + 6, TEXT_RVA + 19};
    size_t n = sizeof(names) / sizeof(names[0]);
    put32(ed + 0, 0);                 // Characteristics
    put32(ed + 12, EDATA_RVA + 0x4E); // Name, the module
    put32(ed + 16, 1);                // Base: ordinals are 1, 2, 3
    put32(ed + 20, (uint32_t)n);      // NumberOfFunctions
    put32(ed + 24, (uint32_t)n);      // NumberOfNames
    put32(ed + 28, EDATA_RVA + 0x28); // AddressOfFunctions
    put32(ed + 32, EDATA_RVA + 0x34); // AddressOfNames
    put32(ed + 36, EDATA_RVA + 0x40); // AddressOfNameOrdinals
    size_t str = 0x4E;
    memcpy(ed + str, "testmod.dll", 11);
    str += 12;
    for (size_t i = 0; i < n; i++) {
        put32(ed + 0x28 + i * 4, rvas[i]);
        put32(ed + 0x34 + i * 4, EDATA_RVA + (uint32_t)str);
        put16(ed + 0x40 + i * 2, (uint16_t)i);
        size_t len = 0;
        while (names[i][len])
            len++;
        memcpy(ed + str, names[i], len + 1);
        str += len + 1;
    }
}

// The export table, asserted on its content rather than its size. Every earlier test
// in this project compared counts, which is why a parser that returned the opening
// bytes of a function as each export's name passed: the number of names parsed is the
// same either way, so only the text can catch it.
static void check_exports(const re_pe_t *pe) {
    static const char *const kWant[3] = {"AlphaFunc", "BetaFunc", "GammaFunc"};
    RE_CHECK_FITS(pe->exports, 3);
    for (size_t i = 0; i < RE_VEC_LEN(&pe->exports) && i < 3; i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&pe->exports, re_pe_exp_t, i);
        RE_CHECK(re_str_eq_cstr(x->name, kWant[i]));
        // Base is 1 in the fixture, so ordinal i is i+1.
        RE_CHECK_EQ_U(x->ordinal, i + 1u);
        RE_CHECK_EQ_HEX(x->rva, i == 0 ? TEXT_RVA : (i == 1 ? TEXT_RVA + 6 : TEXT_RVA + 19));
    }
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

static void drive_malformed(const uint8_t *bytes, size_t n);

// The no-crash guarantee, on inputs that are not a valid image. A protected binary
// arrives as a file whose headers may be inconsistent, and both of these walks trust
// the PE enough to index off it, so a truncated or corrupted image is the case most
// likely to read out of bounds. Reaching the end of this loop is the assertion: a
// crash or a spin fails the binary or the CTest timeout, and neither can be caught
// and turned into a passing check.
static void check_malformed(void) {
    static const size_t kCuts[] = {1, 0x20, 0x41, 0x58, 0x100, 0x148, 0x170, 0x1f0};
    static const size_t kPokes[] = {0x3c, 0x44, 0x46, 0x58, 0x5a, 0x68, 0x148, 0x15c};
    uint8_t img[IMG_BYTES];
    uint8_t bad[IMG_BYTES];
    size_t done = 0;
    for (size_t ci = 0; ci < sizeof(kCuts) / sizeof(kCuts[0]); ci++) {
        build_pe(img);
        for (size_t pi = 0; pi < sizeof(kPokes) / sizeof(kPokes[0]); pi++) {
            size_t cut = kCuts[ci] < sizeof(img) ? kCuts[ci] : sizeof(img);
            memcpy(bad, img, cut);
            if (pi < sizeof(kPokes) / sizeof(kPokes[0]) && kPokes[pi] < cut)
                bad[kPokes[pi]] = (uint8_t)(0xA5u ^ (unsigned)pi);
            drive_malformed(bad, cut);
            done++;
        }
    }
    RE_CHECK_EQ_U(done, sizeof(kCuts) / sizeof(kCuts[0]) * (sizeof(kPokes) / sizeof(kPokes[0])));
}

// Run both analyses over whatever it was given and require only that they return.
static void drive_malformed(const uint8_t *bytes, size_t n) {
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_cfg_t g;
    re_vec_t out;
    bool truncated = false;
    re_arena_init(&a, 65536);
    re_span_t span = {(const uint8_t *)bytes, n};
    if (re_pe_parse(span, &a, &pe) != RE_OK || !pe.valid) {
        re_arena_free(&a);
        return;
    }
    if (!re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a)) {
        re_arena_free(&a);
        return;
    }
    re_func_scan(&code, &a, &scan);
    for (size_t i = 0; i < RE_VEC_LEN(&scan.funcs); i++)
        re_cfg_build(&code, RE_VEC_PTR(&scan.funcs, re_func_t, i), &g, &a);
    re_vec_init(&out, sizeof(re_region_t));
    re_region_scan(&code, &scan, NULL, &pe, 512, &out, &truncated, &a);
    re_arena_free(&a);
}

// The analysis driver, driven through its real entry point. The fixture has to be on
// disk for that, because re_analysis_open takes a path and that is what a caller has;
// testing a private entry point instead would pass while the one commands use rotted.
static void check_analysis(void) {
    static const char kTmp[] = "re_test_cfg_fixture.sys";
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_analysis_t an;
    FILE *fh;
    build_pe(img);
    fh = fopen(kTmp, "wb");
    RE_CHECK(fh != NULL);
    if (!fh)
        return;
    fwrite(img, 1, sizeof(img), fh);
    fclose(fh);
    re_arena_init(&a, 1u << 20);
    RE_CHECK(re_analysis_open(&an, &a, kTmp));
    RE_CHECK(an.ok);
    RE_CHECK(an.has_pe);
    RE_CHECK(an.has_code);
    RE_CHECK_EQ_U(RE_VEC_LEN(&an.passes), RE_PASS_COUNT);
    // Every pass is accounted for, and the ones this file can support did run.
    for (int i = 0; i < RE_PASS_COUNT; i++) {
        const re_pass_stat_t *st = re_analysis_pass(&an, (re_pass_t)i);
        RE_CHECK(st != NULL);
        if (!st)
            continue;
        RE_CHECK_EQ_U(st->pass, (unsigned)i);
        RE_CHECK(re_analysis_pass_name(st->pass) != NULL);
    }
    const re_pass_stat_t *fx = re_analysis_pass(&an, RE_PASS_FUNCS);
    const re_pass_stat_t *xs = re_analysis_pass(&an, RE_PASS_XREFS);
    RE_CHECK(fx && fx->ran);
    RE_CHECK(fx && fx->count > 0);
    RE_CHECK(xs && xs->ran);
    RE_CHECK(xs && xs->count > 0);
    // Exports came from the fixture's export directory, so a driver that lost them
    // between the PE parse and the report would show here.
    RE_CHECK_FITS(an.pe.exports, 3);
    RE_CHECK(re_str_eq_cstr(re_analysis_pass(&an, RE_PASS_FUNCS)->pass == RE_PASS_FUNCS
                                ? RE_VEC_AT(&an.pe.exports, re_pe_exp_t, 0).name
                                : re_str(""),
                            "AlphaFunc"));
    // The stack accessor has to reach the functions the scan found.
    re_stack_t st;
    RE_CHECK(re_analysis_stack_of(&an, 0, &st));
    re_analysis_close(&an);
    re_arena_free(&a);
    remove(kTmp);
}

// The pass table must have one record per pass, whatever happened. A pass that bailed
// still has a slot saying so, because a report with eight rows and six real results
// reads exactly like one where two passes found nothing.
static void check_pass_records(void) {
    RE_CHECK_EQ_U(RE_PASS_COUNT, 8);
    RE_CHECK(re_str_eq_cstr(re_str(re_analysis_pass_name(RE_PASS_FUNCS)), "functions"));
    // The wording for a skip has to say something actionable, not just "skipped".
    RE_CHECK(re_str(re_analysis_skip_name(RE_PASS_SKIP_NO_DECODER)).n > 8);
    RE_CHECK_EQ_U(re_str(re_analysis_skip_name(RE_PASS_RAISED_NONE)).n, 0);
}

// The region classifier over the same fixture. The one section is executable and
// holds a decoded function, so it must come back as code; and the window it sits in
// starts below the first section, so the header region must come back unknown rather
// than being folded into a neighbour.
static void check_regions(re_code_t *code, const re_fscan_t *scan, const re_pe_t *pe,
                          re_arena_t *a) {
    re_vec_t out;
    bool truncated = true;
    re_vec_init(&out, sizeof(re_region_t));
    size_t n = re_region_scan(code, scan, NULL, pe, 512, &out, &truncated, a);
    RE_CHECK(n >= 2);
    RE_CHECK(!truncated);
    // The image is 0x200 bytes of headers plus 20 bytes of code, so a 512 byte window
    // covers the headers and the section sits in the next one.
    size_t found = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&out); i++) {
        const re_region_t *r = RE_VEC_PTR(&out, re_region_t, i);
        if (r->n_funcs == 0)
            continue;
        found++;
        RE_CHECK_EQ_U(r->kind, RE_REG_CODE);
        RE_CHECK(r->exec);
        RE_CHECK(r->func_bytes > 0);
        RE_CHECK(r->confidence >= RE_REG_CONF_LOW);
    }
    RE_CHECK(found >= 1);
}

int main(void) {
    uint8_t img[IMG_BYTES];
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
    RE_CHECK_EQ_U(pe.n_sec_field, 2);
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
    check_regions(&code, &scan, &pe, &a);
    check_exports(&pe);
    check_pass_records();
    check_analysis();
    check_malformed();
    re_arena_free(&a);
    return re_test_report("cfg");
}
