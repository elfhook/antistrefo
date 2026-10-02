// test_features.c - checks the step two features: search, demangling, time, entropy.
// Module: test (C11).
// Owns: correctness checks for re_search, re_demangle, re_time and re_entropy.
// Depends: re_core and re_utils. Prints to stdout, which is fine for a test binary.
#include "features/data/re_search.h"
#include "features/lib/re_demangle.h"
#include "features/lib/re_flirt.h"
#include "utils/sys/re_entropy.h"
#include "utils/sys/re_time.h"
#include "utils/text/re_util.h"
#include "re_test.h"

#include <stdio.h>
#include <string.h>

static void test_time(void) {
    char buf[24];
    re_time_iso(0, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "1970-01-01T00:00:00Z") == 0);
    // 1262079379 is 14607 days after the epoch, which is three days short of
    // 2010, so this lands in 2009. Getting this right is why the check exists.
    re_time_iso(1262079379, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "2009-12-29T09:36:19Z") == 0);
    re_time_iso(1, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "1970-01-01T00:00:01Z") == 0);
    re_time_iso(1583020800, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "2020-03-01T00:00:00Z") == 0);
    re_time_iso(1767225600, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "2026-01-01T00:00:00Z") == 0);
    // A timestamp before the epoch, which pre 1970 builds produce.
    re_time_iso(-86400, buf, sizeof(buf));
    RE_CHECK(strcmp(buf, "1969-12-31T00:00:00Z") == 0);
    RE_CHECK_EQ_U(re_time_year(1262079379), 2009);
    RE_CHECK_EQ_U(re_time_year(0), 1970);
    RE_CHECK_EQ_U(re_time_age_years(0, 1262079379), 39);
    RE_CHECK_EQ_U(re_time_year(1767225600), 2026);
}

// The haystack the search tests run against, plus the offsets of the pieces they
// look for. Built in pieces so every expected offset is exact rather than hand
// counted, and no hex escape can swallow the bytes after it.
typedef struct {
    re_span_t img;
    size_t pattern;
    size_t needle;
    size_t wide;
    size_t imm;
    size_t main;
} hay_t;

static hay_t make_hay(uint8_t *buf) {
    static const uint8_t pat4[4] = {0xde, 0xad, 0xbe, 0xef};
    static const uint8_t needle[6] = {'N', 'E', 'E', 'D', 'L', 'E'};
    size_t n = 0;
    hay_t h;
    memcpy(buf + n, "AAAA", 4);
    n += 4;
    memcpy(buf + n, pat4, 4);
    h.pattern = n;
    n += 4;
    memcpy(buf + n, "domain", 6);
    n += 6;
    buf[n++] = ' ';
    memcpy(buf + n, "main", 4);
    h.main = n;
    n += 4;
    buf[n++] = ' ';
    memcpy(buf + n, needle, 6);
    h.needle = n;
    n += 6;
    memcpy(buf + n, needle, 6);
    h.wide = n;
    for (size_t i = 0; i < 6; i++) {
        buf[n] = needle[i];
        buf[n + 1] = 0;
        n += 2;
    }
    buf[n++] = 0xad;
    buf[n++] = 0x00;
    h.imm = n - 2;
    memcpy(buf + n, "ZZZZ", 4);
    n += 4;
    h.img = re_span(buf, n);
    return h;
}

// A wildcard byte matches anything, and a non matching literal is a miss. Bad
// and ambiguous patterns are refused rather than guessed at.
static void test_search_patterns(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    uint8_t *by = NULL;
    uint8_t *mk = NULL;
    size_t pn = 0;
    RE_CHECK(re_search_parse_pattern(a, "deadbe??", &by, &mk, &pn, NULL));
    RE_CHECK_EQ_U(pn, 4);
    RE_CHECK_EQ_U(mk[0], 0xFF);
    RE_CHECK_EQ_U(mk[3], 0);
    re_search_init(&s);
    re_search_bytes(h->img, by, mk, pn, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    RE_CHECK(re_search_parse_pattern(a, "deadbe00", &by, &mk, &pn, NULL));
    re_search_init(&s);
    re_search_bytes(h->img, by, mk, pn, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 0);
    RE_CHECK(!re_search_parse_pattern(a, "deaz", &by, &mk, &pn, NULL));
    RE_CHECK(!re_search_parse_pattern(a, "d", &by, &mk, &pn, NULL));
    RE_CHECK(!re_search_parse_pattern(a, "dead?ebe?", &by, &mk, &pn, NULL));
    RE_CHECK(re_search_parse_pattern(a, "deadbeef", &by, &mk, &pn, NULL));
    re_search_init(&s);
    re_search_bytes(h->img, by, mk, pn, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->pattern);
}

// Both endiannesses, so 0x00AD matches ad 00 and also 00 ad where the high byte
// of the preceding wide character happens to be zero.
static void test_search_immediate(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_immediate(h->img, 0xDEADBEEFu, 4, true, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->pattern);
    re_search_init(&s);
    re_search_immediate(h->img, 0x00ADu, 2, true, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    RE_CHECK_FITS(s.hits, 2);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->imm);
    if (RE_VEC_LEN(&s.hits) > 1)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 1).off, h->imm - 1);
}

// A hit list must name each offset once. The wide scan used to rebuild a run
// once per character, so one match was reported several times over.
static void check_offsets_distinct(const re_search_t *s) {
    for (size_t i = 0; i < RE_VEC_LEN(&s->hits); i++) {
        for (size_t j = i + 1; j < RE_VEC_LEN(&s->hits); j++) {
            if (RE_VEC_AT(&s->hits, re_search_hit_t, i).off ==
                RE_VEC_AT(&s->hits, re_search_hit_t, j).off)
                RE_CHECK(0 && "duplicate hit offset");
        }
    }
}

// Text search must find both the ascii copy and the narrowed utf-16 copy, and a
// regex must also see through the wide copy.
static void test_search_text(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_text(h->img, re_str("NEEDLE"), false, false, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    check_offsets_distinct(&s);
    re_search_init(&s);
    re_search_text(h->img, re_str("needle"), false, true, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    RE_CHECK_FITS(s.hits, 2);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->needle);
    if (RE_VEC_LEN(&s.hits) > 1)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 1).off, h->wide);
    re_search_init(&s);
    re_search_text(h->img, re_str("NEE.LE"), true, false, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 2);
    check_offsets_distinct(&s);
    // A one letter pattern over a wide run is where the duplication showed up,
    // because every other byte of the run looked like a fresh run start.
    re_search_init(&s);
    re_search_text(h->img, re_str("E"), false, false, false, 0, 0, a, &s);
    check_offsets_distinct(&s);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), s.total);
}

// A signature style search must not match inside a longer word, so the standalone
// main is a hit while the one inside domain is a miss.
static void test_search_signature(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_signature(h->img, re_str("main"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    RE_CHECK_FITS(s.hits, 1);
    if (RE_VEC_LEN(&s.hits) > 0)
        RE_CHECK_EQ_U(RE_VEC_AT(&s.hits, re_search_hit_t, 0).off, h->main);
    re_search_init(&s);
    re_search_signature(h->img, re_str("doma"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 0);
}

// The limit caps what is kept and the scan stops there, so total is a floor and
// more has to say so. A limited search must never look complete when it is not.
static void test_search_limit(re_arena_t *a, const hay_t *h) {
    re_search_t s;
    re_search_init(&s);
    re_search_text(h->img, re_str("NEEDLE"), false, false, false, 0, 1, a, &s);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), 1);
    RE_CHECK_EQ_U(s.total, 1);
    RE_CHECK(s.more);
    // The same search uncapped reports both copies and does not claim otherwise.
    re_search_init(&s);
    re_search_text(h->img, re_str("NEEDLE"), false, false, false, 0, 0, a, &s);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), 2);
    RE_CHECK_EQ_U(s.total, 2);
    RE_CHECK(!s.more);
    // The whole word matcher must not report a prefix of a longer word.
    re_search_init(&s);
    re_search_signature(h->img, re_str("main"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 1);
    re_search_init(&s);
    re_search_signature(h->img, re_str("mai"), 0, 0, a, &s);
    RE_CHECK_EQ_U(s.total, 0);
}

static void test_search(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    uint8_t buf[256];
    hay_t h = make_hay(buf);
    test_search_patterns(&a, &h);
    test_search_immediate(&a, &h);
    test_search_text(&a, &h);
    test_search_signature(&a, &h);
    test_search_limit(&a, &h);
    re_arena_free(&a);
}

static void test_demangle(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    re_str_t out;
    // Lengths come from strlen. Hand counting a mangled symbol is how you end
    // up debugging a truncated string that was never truncated.
#define DEMANGLE(sym) re_demangle_itanium(&a, (sym), strlen(sym), &out)
    RE_CHECK_EQ_U(re_mangle_kind("main", 4), RE_MANGLE_UNKNOWN);
    RE_CHECK_EQ_U(re_mangle_kind("_ZN3foo3barEv", 13), RE_MANGLE_ITANIUM);
    RE_CHECK_EQ_U(re_mangle_kind("?func@@YAXXZ", 12), RE_MANGLE_MSVC);
    RE_CHECK_EQ_U(re_mangle_kind("main", 4), RE_MANGLE_UNKNOWN);
    RE_CHECK_EQ_U(re_mangle_kind("_ZN3foo3barEv", 13), RE_MANGLE_ITANIUM);
    RE_CHECK_EQ_U(re_mangle_kind("?func@@YAXXZ", 12), RE_MANGLE_MSVC);
    RE_CHECK(DEMANGLE("_ZN3foo3barEv"));
    RE_CHECK(strcmp(out.p, "foo::bar()") == 0);
    // The same symbol again in the same process. imports and exports demangle
    // many symbols per run, so a parser that carried state between calls only
    // showed up on the second one, which is what this pins down.
    RE_CHECK(DEMANGLE("_ZN3foo3barEv"));
    RE_CHECK(strcmp(out.p, "foo::bar()") == 0);
    RE_CHECK(DEMANGLE("_ZN3foo3barEvi"));
    RE_CHECK(strcmp(out.p, "foo::bar(int)") == 0);
    RE_CHECK(DEMANGLE("_ZN5Outer5Inner3fooEv"));
    RE_CHECK(strcmp(out.p, "Outer::Inner::foo()") == 0);
    // A member function template renders its arguments on the template name,
    // and a template parameter whose type is unknown says so rather than failing.
    RE_CHECK(DEMANGLE("_ZN3foo3barIiEEvT_"));
    RE_CHECK(strcmp(out.p, "foo::bar<int>(auto)") == 0);
    // A substitution reference resolves through the pool.
    RE_CHECK(DEMANGLE("_ZN1a1bES_"));
    RE_CHECK(strcmp(out.p, "a::b()") == 0);
    // Malformed input is refused rather than guessed at.
    RE_CHECK(!DEMANGLE("_ZN3fo"));
    RE_CHECK(!DEMANGLE("not_mangled"));
    RE_CHECK(!DEMANGLE("_ZN3foo3bar"));
    RE_CHECK(re_demangle_msvc(&a, "?func@@YAXXZ", strlen("?func@@YAXXZ"), &out));
    RE_CHECK(strcmp(out.p, "func()") == 0);
    RE_CHECK(re_demangle_msvc(&a, "?f@@YAHH@Z", strlen("?f@@YAHH@Z"), &out));
    RE_CHECK(strcmp(out.p, "f(int)") == 0);
#undef DEMANGLE
    re_arena_free(&a);
}

static void test_entropy(void) {
    // Uniform data is maximal, a single repeated byte is zero.
    uint8_t zero[512];
    for (int i = 0; i < 512; i++)
        zero[i] = 0;
    re_span_t z = re_span(zero, 512);
    RE_CHECK(re_entropy(z) < 0.0001);
    size_t counts[2] = {256, 256};
    RE_CHECK(re_entropy_of_counts(counts, 2) > 0.999 && re_entropy_of_counts(counts, 2) < 1.001);
    size_t empty[2] = {0, 0};
    RE_CHECK_EQ_U((uint64_t)re_entropy_of_counts(empty, 2), 0);
    RE_CHECK_EQ_U((uint64_t)re_entropy(re_span_none()), 0);
}

// The signature file is the only route to naming a library function, so the loader
// is pinned on its whole surface: the documented spacing, wildcards, slack, and the
// lines that must be refused. The spacing case is the one that was broken. A pattern
// written as " 488bc453" is not a hex pair, so every signature in a valid file loaded,
// was counted, and matched nothing - which reads as "the tool does not work" rather
// than as a parser bug.
static void test_flirt(void) {
    re_arena_t a;
    re_vec_t sigs;
    re_arena_init(&a, 65536);
    re_vec_init(&sigs, sizeof(re_sig_t));
    re_vec_clear(&sigs);
    RE_CHECK_EQ_U(re_flirt_builtin(&a, &sigs), 3);
    const char *path = "re_flirt_probe.sig";
    FILE *fh = fopen(path, "wb");
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
    size_t added = re_flirt_load(&a, path, &sigs);
    // Four accepted: spaced, tight, wildcarded and slack.
    RE_CHECK_EQ_U(added, 4);
    // The built in idioms must survive loading a file. They used to be cleared, so
    // asking for a signature file silently cost the three built in patterns.
    RE_CHECK_EQ_U(RE_VEC_LEN(&sigs), 7);
    const re_sig_t *s = RE_VEC_PTR(&sigs, re_sig_t, 3);
    RE_CHECK(re_str_eq_cstr(s->name, "Spaced"));
    RE_CHECK(re_str_eq_cstr(s->module, "mod"));
    RE_CHECK(re_str_eq_cstr(s->pattern, "488bc453"));
    RE_CHECK_EQ_U(s->slack, 0);
    RE_CHECK(re_str_eq_cstr(RE_VEC_PTR(&sigs, re_sig_t, 4)->name, "Tight"));
    RE_CHECK(re_str_eq_cstr(RE_VEC_PTR(&sigs, re_sig_t, 5)->pattern, "488b????"));
    // Slack was documented, never parsed, and the matcher never looked at it.
    RE_CHECK_EQ_U(RE_VEC_PTR(&sigs, re_sig_t, 6)->slack, 4);
    // A path that is not there adds nothing and takes nothing away.
    RE_CHECK_EQ_U(re_flirt_load(&a, "re_flirt_absent.sig", &sigs), 0);
    RE_CHECK_EQ_U(RE_VEC_LEN(&sigs), 7);
    remove(path);
    re_arena_free(&a);
}

int re_test_features(void) {
    test_time();
    test_search();
    test_demangle();
    test_entropy();
    test_flirt();
    return 0;
}
