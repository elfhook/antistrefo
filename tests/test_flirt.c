// test_flirt.c - the signature compiler, the matcher, the byte index and the loaders.
// Module: test (C11).
// Owns: what each pattern operator means, what is refused, and which name wins.
// Depends: re_flirt through its public header and the shared PE fixture, so every
//           match is decided against real decoded bytes rather than a stand in.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/lib/re_flirt.h"
#include "features/lib/re_sigfile.h"
#include "features/meta/re_disasm.h"
#include "utils/mem/re_arena.h"

#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// Fill a signature from text. Every field the compiler is allowed to read is set,
// because a signature whose n is left at zero claims nothing and would make a test
// that forgot to compile it pass for the wrong reason.
static void build(re_arena_t *a, re_sig_t *s, const char *text, uint8_t slack) {
    memset(s, 0, sizeof(*s));
    s->name = re_str("probe");
    s->module = re_str("test");
    s->pattern = re_str(re_arena_strdup(a, text));
    s->slack = slack;
}

// Every operator, asserted on the kind and the value of the byte it produced. A test
// that only checked the compiled length would pass for a compiler that turned a
// negative match into an ordinary one, which is the difference between a signature
// that names the right function and one that names the wrong one.
static void check_operators(re_arena_t *a) {
    re_sig_t s;
    build(a, &s, "488bc453", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.n, 4);
    RE_CHECK_EQ_U(s.kind[0], RE_SIGK_EXACT);
    RE_CHECK_EQ_HEX(s.want[0], 0x48);
    RE_CHECK_EQ_HEX(s.want[3], 0x53);

    build(a, &s, "48??c4", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.n, 3);
    RE_CHECK_EQ_U(s.kind[1], RE_SIGK_ANY);

    build(a, &s, "48!c8c4", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.n, 3);
    RE_CHECK_EQ_U(s.kind[1], RE_SIGK_NOT);
    RE_CHECK_EQ_HEX(s.want[1], 0xc8);

    // One nibble fixed, either half. A high nibble keeps its value in the top four
    // bits so the matcher can compare it without a second table.
    build(a, &s, "4?", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.kind[0], RE_SIGK_HI);
    RE_CHECK_EQ_HEX(s.want[0], 0x40);
    build(a, &s, "?8", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.kind[0], RE_SIGK_LO);
    RE_CHECK_EQ_HEX(s.want[0], 0x08);

    // A relocation is four bytes the pattern says nothing about, written as one token.
    build(a, &s, "48@53", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.n, 6);
    RE_CHECK_EQ_U(s.kind[0], RE_SIGK_EXACT);
    RE_CHECK_EQ_U(s.kind[1], RE_SIGK_ANY);
    RE_CHECK_EQ_U(s.kind[4], RE_SIGK_ANY);
    RE_CHECK_EQ_U(s.kind[5], RE_SIGK_EXACT);
    RE_CHECK_EQ_HEX(s.want[5], 0x53);

    // Spaces between tokens are a readability allowance, and the comma-free form has
    // to mean exactly the same thing as the packed one.
    build(a, &s, "48 8b c4", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.n, 3);
    RE_CHECK_EQ_HEX(s.want[1], 0x8b);
}

// What the compiler refuses. Each of these is a pattern that would otherwise be
// counted as a loaded signature and match nothing, or worse, match loosely.
static void check_refusals(re_arena_t *a) {
    re_sig_t s;
    build(a, &s, "", 0);
    RE_CHECK(!re_sig_compile(&s));
    build(a, &s, "?", 0);
    RE_CHECK(!re_sig_compile(&s));
    build(a, &s, "4", 0);
    RE_CHECK(!re_sig_compile(&s));
    build(a, &s, "!zz", 0);
    RE_CHECK(!re_sig_compile(&s));
    build(a, &s, "48g", 0);
    RE_CHECK(!re_sig_compile(&s));
    build(a, &s, "488", 0);
    RE_CHECK(!re_sig_compile(&s));
    // Slack that covers the whole pattern claims nothing, so it can never match and
    // must be refused rather than counted as coverage.
    build(a, &s, "4883f8", 3);
    RE_CHECK(!re_sig_compile(&s));
    build(a, &s, "4883f8", 4);
    RE_CHECK(!re_sig_compile(&s));
    // Exactly the ceiling: allowed, because the bound is on the compiled bytes and
    // not on the text that spells them.
    char big[(RE_SIG_MAX + 1) * 2 + 1];
    for (size_t i = 0; i < RE_SIG_MAX * 2; i++)
        big[i] = "48"[i & 1u];
    big[RE_SIG_MAX * 2] = 0;
    build(a, &s, big, 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK_EQ_U(s.n, RE_SIG_MAX);
    // One byte over it. The compiler owns the bound, so a pattern that would overflow
    // the fixed per signature arrays is refused here and not by the matcher.
    for (size_t i = 0; i < (RE_SIG_MAX + 1) * 2; i++)
        big[i] = "48"[i & 1u];
    big[(RE_SIG_MAX + 1) * 2] = 0;
    build(a, &s, big, 0);
    RE_CHECK(!re_sig_compile(&s));
}

// Matching, against the fixture's first function, whose opening bytes are
// 48 83 f8 01. Every case here is one a reader would write by hand.
static void check_matching(re_code_t *code) {
    re_arena_t a;
    re_sig_t s;
    re_arena_init(&a, 16384);
    build(&a, &s, "4883f801", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // A wrong byte inside the claim is a miss, not a near match.
    build(&a, &s, "4883f802", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    // A negative match: the byte must not be this one.
    build(&a, &s, "4883f8!01", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    build(&a, &s, "4883f8!02", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // Nibble wildcards, one that fits and one that does not.
    build(&a, &s, "4?83f801", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    build(&a, &s, "5?83f801", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    build(&a, &s, "?883f801", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // A relocation slot, matching whatever the four bytes happen to be.
    build(&a, &s, "4883f8@", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // Slack excuses exactly the trailing bytes it names, and no more.
    build(&a, &s, "4883f8ff", 1);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // A wrong byte that slack does not reach is still a miss: with one byte of slack
    // only the first byte is compared, and that one is wrong here.
    build(&a, &s, "58ff", 1);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    // A signature that was never compiled claims nothing. It is not treated as an
    // empty pattern that matches everything.
    build(&a, &s, "4883f801", 0);
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    // A pattern longer than the bytes left in the section is a miss rather than a
    // partial hit.
    build(&a, &s, "4883f801", 0);
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA + sizeof(kCode) - 1, &s));
    re_arena_free(&a);
}

// The index must answer exactly what a walk over the whole set would, or a name
// depends on which bucket a signature happened to land in.
static void check_index(re_code_t *code, re_fscan_t *scan) {
    re_arena_t a;
    re_vec_t sigs;
    re_sigdb_t db;
    re_arena_init(&a, 16384);
    re_vec_init(&sigs, sizeof(re_sig_t));
    // Three signatures that all match the fixture's first function, so the winner is
    // decided by strength rather than by luck: the wildcarded one first, an exact one
    // second. The exact first byte is the stronger claim and must win.
    re_sig_t s;
    build(&a, &s, "??83f801", 0);
    s.name = re_str("weak");
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    RE_VEC_PUSH(&sigs, &a, s);
    build(&a, &s, "4883f801", 0);
    s.name = re_str("strong");
    RE_CHECK(re_sig_compile(&s));
    RE_VEC_PUSH(&sigs, &a, s);
    re_sigdb_build(&a, &sigs, &db);
    RE_CHECK_EQ_U(db.n, 2);
    for (size_t i = 0; i < RE_VEC_LEN(&scan->funcs); i++) {
        const re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, i);
        re_str_t nm;
        re_str_t mod;
        bool hit = re_sigdb_name(&db, code, f, &nm, &mod);
        // Soundness: a name is only produced when some pattern in the set actually
        // matched at that address. Completeness: if any pattern matched, the index
        // must find it. Together these are what a bucket bug breaks.
        bool any = false;
        for (size_t k = 0; k < RE_VEC_LEN(&sigs); k++) {
            if (re_sig_match(code, f->va, RE_VEC_PTR(&sigs, re_sig_t, k)))
                any = true;
        }
        RE_CHECK(hit == any);
        if (i == 0) {
            // Both patterns match the first function, so the answer says which one
            // the index prefers: the exact first byte, not the wildcard that happens
            // to sit earlier in the set.
            RE_CHECK(hit);
            RE_CHECK(re_str_eq_cstr(nm, "strong"));
            RE_CHECK_EQ_U(mod.n, 4);
        }
    }
    re_arena_free(&a);
}

// The built in database, asserted on its content. A count alone would pass for a
// database that had lost the names and kept the patterns.
static void check_builtin(void) {
    static const char *const kWant[] = {
        "gs_cookie_init",
        "gs_cookie_read",
        "guard_dispatch_icall",
        "__security_check_cookie",
        "__chkstk",
        "memcpy",
        "memset",
        "memcmp",
        "strlen",
        "strcat",
        "strcpy",
        "strcmp",
    };
    re_arena_t a;
    re_vec_t sigs;
    re_arena_init(&a, 65536);
    re_vec_init(&sigs, sizeof(re_sig_t));
    size_t n = re_flirt_builtin(&a, &sigs);
    RE_CHECK(n >= sizeof(kWant) / sizeof(kWant[0]));
    RE_CHECK_EQ_U(RE_VEC_LEN(&sigs), n);
    for (size_t i = 0; i < RE_VEC_LEN(&sigs); i++) {
        const re_sig_t *s = RE_VEC_PTR(&sigs, re_sig_t, i);
        // Every entry must compile, or it is a line that can never match and the
        // count above is a claim about a database that does nothing.
        RE_CHECK(s->n > 0);
        RE_CHECK(s->name.n > 0);
        RE_CHECK(s->module.n > 0);
        // A claim can never be shorter than the bytes the text spells out, so a
        // compiler that stopped early is caught here. It can be longer, because one
        // relocation token stands for four bytes.
        RE_CHECK(s->n >= s->pattern.n / 2);
    }
    for (size_t k = 0; k < sizeof(kWant) / sizeof(kWant[0]); k++) {
        bool found = false;
        for (size_t i = 0; i < RE_VEC_LEN(&sigs); i++) {
            if (re_str_eq_cstr(RE_VEC_PTR(&sigs, re_sig_t, i)->name, kWant[k]))
                found = true;
        }
        RE_CHECK(found);
    }
    re_arena_free(&a);
}

// The file reader, including what it refuses. A line that looks like a signature and
// cannot compile must be counted as refused, because a signature that cannot match
// anything reads exactly like a database that found nothing.
static void check_loader(void) {
    re_arena_t a;
    re_vec_t sigs;
    re_flirt_load_stat_t stat;
    const char *path = "re_flirt_probe.sig";
    FILE *fh;
    re_arena_init(&a, 65536);
    re_vec_init(&sigs, sizeof(re_sig_t));
    re_flirt_builtin(&a, &sigs);
    size_t built = RE_VEC_LEN(&sigs);
    fh = fopen(path, "wb");
    RE_CHECK(fh != NULL);
    if (!fh) {
        re_arena_free(&a);
        return;
    }
    const char *body = "Spaced : mod : 488bc453\n"
                       "Tight:mod:488bc453\n"
                       "Wild : mod : 488b????\n"
                       "Slack : mod : 488bc453 : 4\n"
                       "# a comment\n"
                       "\n"
                       "NoColons\n"
                       "BadHex : mod : 488g\n"
                       "OddLen : mod : 488\n"
                       "EmptyName : mod :\n"
                       "TooMuchSlack : mod : 488bc453 : 9\n";
    fwrite(body, 1, strlen(body), fh);
    fclose(fh);
    size_t added = re_flirt_load_ex(&a, path, &sigs, &stat);
    // Three accepted: the spaced one, the tight one and the wildcarded one. The slack
    // entry is refused because its slack covers the whole pattern, which is a
    // signature that can never fire.
    RE_CHECK_EQ_U(added, 3);
    RE_CHECK_EQ_U(stat.loaded, 3);
    RE_CHECK_EQ_U(stat.rejected, 6);
    RE_CHECK_EQ_U(stat.skipped, 2);
    RE_CHECK_EQ_U(stat.before, built);
    // The built in idioms must survive loading a file.
    RE_CHECK_EQ_U(RE_VEC_LEN(&sigs), built + 3);
    const re_sig_t *s = RE_VEC_PTR(&sigs, re_sig_t, built);
    RE_CHECK(re_str_eq_cstr(s->name, "Spaced"));
    RE_CHECK(re_str_eq_cstr(s->module, "mod"));
    RE_CHECK(re_str_eq_cstr(s->pattern, "488bc453"));
    RE_CHECK_EQ_U(s->slack, 0);
    RE_CHECK_EQ_U(s->n, 4);
    s = RE_VEC_PTR(&sigs, re_sig_t, built + 1);
    RE_CHECK(re_str_eq_cstr(s->name, "Tight"));
    RE_CHECK_EQ_U(s->n, 4);
    s = RE_VEC_PTR(&sigs, re_sig_t, built + 2);
    RE_CHECK_EQ_U(s->kind[2], RE_SIGK_ANY);
    // A path that is not there adds nothing and takes nothing away.
    stat.loaded = 99;
    RE_CHECK_EQ_U(re_flirt_load_ex(&a, "re_flirt_absent.sig", &sigs, &stat), 0);
    RE_CHECK_EQ_U(stat.loaded, 0);
    RE_CHECK_EQ_U(stat.rejected, 0);
    RE_CHECK_EQ_U(RE_VEC_LEN(&sigs), built + 3);
    remove(path);
    re_arena_free(&a);
}

// The .pat dialect is a translation into the native language, so the cases that matter
// are the ones where the two spellings differ: a whole byte wildcard, a half byte
// wildcard, the entry framing, and an entry the reader has to refuse. The header's crc
// is kept and its length is checked for shape only, so a header that is not one cannot
// become a signature whose name is a fragment of something else.
static void check_pat(void) {
    re_arena_t a;
    re_vec_t sigs;
    re_flirt_load_stat_t stat;
    const char *path = "re_flirt_probe.pat";
    FILE *fh;
    re_arena_init(&a, 65536);
    re_vec_init(&sigs, sizeof(re_sig_t));
    fh = fopen(path, "wb");
    RE_CHECK(fh != NULL);
    if (!fh) {
        re_arena_free(&a);
        return;
    }
    const char *body = "3A1F 0008 memcpy\r\n"
                       "48 8B C1 4C 8D 15 .. .. .. .. 49 83 F8 0F\r\n"
                       "---\r\n"
                       "--------\r\n"
                       "0000 0004 probe_half\r\n"
                       "48 8. C1 ?1\r\n"
                       "--------\r\n"
                       "not a header line\r\n"
                       "48 8B\r\n"
                       "--------\r\n";
    fwrite(body, 1, strlen(body), fh);
    fclose(fh);
    size_t added = re_sigfile_pat(&a, path, &sigs, &stat);
    RE_CHECK_EQ_U(added, 2);
    RE_CHECK_EQ_U(stat.loaded, 2);
    RE_CHECK_EQ_U(stat.rejected, 1);
    RE_CHECK_EQ_U(stat.skipped, 1);
    const re_sig_t *s = RE_VEC_PTR(&sigs, re_sig_t, 0);
    RE_CHECK_EQ_U(s->n, 14);
    RE_CHECK_EQ_U(s->kind[6], RE_SIGK_ANY);
    RE_CHECK_EQ_U(s->kind[5], RE_SIGK_EXACT);
    RE_CHECK(s->has_crc);
    RE_CHECK_EQ_HEX(s->crc, 0x3a1f);
    // The module is the file's own name: a .pat does not state one per entry, and the
    // file that claimed the name is the honest answer.
    RE_CHECK(re_str_eq_cstr(s->module, "re_flirt_probe.pat"));
    s = RE_VEC_PTR(&sigs, re_sig_t, 1);
    RE_CHECK_EQ_U(s->n, 4);
    RE_CHECK_EQ_U(s->kind[1], RE_SIGK_HI);
    RE_CHECK_EQ_HEX(s->want[1], 0x80);
    RE_CHECK_EQ_U(s->kind[3], RE_SIGK_LO);
    RE_CHECK_EQ_HEX(s->want[3], 0x01);
    remove(path);
    re_arena_free(&a);
}

// The dispatcher sends a name that does not end in .pat to the native reader, so a
// caller does not have to know which dialect a file is written in before asking.
static void check_pat_dispatch(void) {
    re_arena_t a;
    re_vec_t sigs;
    re_flirt_load_stat_t stat;
    const char *path = "re_flirt_probe.sig";
    const char *body = "native : mod : 488bc453\n";
    FILE *fh;
    re_arena_init(&a, 16384);
    re_vec_init(&sigs, sizeof(re_sig_t));
    fh = fopen(path, "wb");
    RE_CHECK(fh != NULL);
    if (!fh) {
        re_arena_free(&a);
        return;
    }
    fwrite(body, 1, strlen(body), fh);
    fclose(fh);
    RE_CHECK_EQ_U(re_sigfile_load(&a, path, &sigs, &stat), 1);
    RE_CHECK(re_str_eq_cstr(RE_VEC_PTR(&sigs, re_sig_t, 0)->name, "native"));
    // And the same file asked for as a .pat is read as one, which is what makes the
    // suffix the reader's whole decision rather than a hint it may ignore.
    RE_CHECK_EQ_U(re_sigfile_load(&a, "re_flirt_absent.pat", &sigs, &stat), 0);
    RE_CHECK_EQ_U(stat.loaded, 0);
    remove(path);
    re_arena_free(&a);
}

int main(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_arena_init(&a, 65536);
    build_pe(img);
    re_pe_parse(re_span(img, sizeof(img)), &a, &pe);
    RE_CHECK(pe.valid);
    check_operators(&a);
    check_refusals(&a);
    check_builtin();
    check_loader();
    check_pat();
    check_pat_dispatch();
    {
        // Matching needs a decoded image, so the code layer is stood up for it.
        re_arena_t a2;
        re_code_t code;
        re_fscan_t scan;
        re_arena_init(&a2, 65536);
        if (re_code_init(&code, re_span(img, sizeof(img)), &pe, re_disasm_find("x86-64"), &a2)) {
            re_func_scan(&code, &a2, &scan);
            check_matching(&code);
            check_index(&code, &scan);
        }
        re_arena_free(&a2);
    }
    re_arena_free(&a);
    return re_test_report("flirt");
}
