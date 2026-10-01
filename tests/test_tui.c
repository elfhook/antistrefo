// test_tui.c - the layout math of the framed report, checked without a terminal.
// Module: test (C11).
// Owns: checks on column counting, clipping, box geometry and panel composition.
// Depends: re_core through re_tui.h. Every case here is one where a wrong answer
// looks plausible on screen, so the numbers are pinned rather than eyeballed.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils/re_arena.h"
#include "utils/re_strbuf.h"
#include "utils/re_tui.h"

// This suite is its own binary, so it owns its counters.
int re_test_count = 0;
int re_test_fail = 0;

// A string comparison that says what differed, because a layout test that only says
// "failed" is a test you have to re-run with a debugger to act on.
#define CHECK_STR(got, want)                                                    \
    do {                                                                        \
        re_test_count++;                                                        \
        const char *g_ = (got);                                                 \
        const char *w_ = (want);                                                \
        if (!g_ || strcmp(g_, w_) != 0) {                                       \
            re_test_fail++;                                                     \
            printf("FAIL %s:%d  got \"%s\"  want \"%s\"\n", __FILE__, __LINE__, \
                   g_ ? g_ : "(null)", w_);                                     \
            fflush(stdout);                                                     \
        }                                                                       \
    } while (0)

typedef struct {
    re_strbuf_t out;
    re_strbuf_t scratch;
    re_tui_t t;
} rig_t;

static void rig_init(rig_t *r, re_arena_t *a, uint16_t width, bool color, bool unicode) {
    re_strbuf_init(&r->out, a);
    re_strbuf_init(&r->scratch, a);
    re_tui_init(&r->t, &r->out, &r->scratch, color, unicode, width);
}

static const char *out_of(const rig_t *r) {
    return r->out.p ? r->out.p : "";
}

// Counting columns is the one thing every other measurement depends on, so it is
// pinned for the cases that would otherwise shift a box silently.
static void test_cols(void) {
    RE_CHECK_EQ_U(re_tui_cols(""), 0);
    RE_CHECK_EQ_U(re_tui_cols("abc"), 3);
    RE_CHECK_EQ_U(re_tui_cols("0x1130"), 6);
    // Two, three and four byte sequences are one column each, not their byte count.
    RE_CHECK_EQ_U(re_tui_cols("\xc2\xb5"), 1);
    RE_CHECK_EQ_U(re_tui_cols("\xe2\x94\x8c"), 1);
    RE_CHECK_EQ_U(re_tui_cols("\xf0\x9f\x94\x8d"), 1);
    // A combining mark adds no column of its own.
    RE_CHECK_EQ_U(re_tui_cols("e\xcc\x81"), 1);
    RE_CHECK_EQ_U(re_tui_cols_span("abcdef", 3), 3);
    // A span cut in the middle of a sequence must not run past the end.
    RE_CHECK_EQ_U(re_tui_cols_span("\xe2\x94", 2), 1);
}

// Clipping has to cut on a character boundary, or the output stops being decodable
// and the whole report after it is affected.
static void test_clip(re_arena_t *a) {
    rig_t r;
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "short", 10);
    CHECK_STR(out_of(&r), "short");
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "abcdefghij", 5);
    RE_CHECK_EQ_U(re_tui_cols(out_of(&r)), 5);
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "", 5);
    CHECK_STR(out_of(&r), "");
    // A multi-byte character must be cut whole, so the byte count can be less than
    // the column count requested without running past the string.
    rig_init(&r, a, 40, false, true);
    re_tui_clip(r.out.p ? &r.out : &r.out, &r.t, "\xe2\x94\x8c\xe2\x94\x8c\xe2\x94\x8c", 2);
    RE_CHECK_EQ_U(re_tui_cols(out_of(&r)), 2);
    // Padding pads to the requested columns, and clips rather than overflowing.
    rig_init(&r, a, 40, false, true);
    re_tui_pad(&r.out, &r.t, "ab", 6);
    CHECK_STR(out_of(&r), "ab    ");
    rig_init(&r, a, 40, false, true);
    re_tui_pad(&r.out, &r.t, "abcdefgh", 4);
    RE_CHECK_EQ_U(re_tui_cols(out_of(&r)), 4);
}

// Every line of a composed row must be exactly the terminal width. A ragged right
// edge is the single most visible way for a framed report to look broken, and it is
// invisible in a test that only checks the text.
static void test_compose_even(re_arena_t *a) {
    static const uint16_t kWidths[] = {40, 60, 80, 100, 120, 200};
    for (size_t w = 0; w < sizeof(kWidths) / sizeof(kWidths[0]); w++) {
        for (unsigned np = 1; np <= RE_TUI_MAX_PANELS; np++) {
            rig_t r;
            re_panel_t p[RE_TUI_MAX_PANELS];
            size_t tallest = 1;
            rig_init(&r, a, kWidths[w], false, true);
            for (unsigned i = 0; i < np; i++) {
                char title[16];
                size_t want = i * 2 + 1;
                snprintf(title, sizeof(title), "Panel %u", i);
                re_panel_init(&p[i], a, title, (uint16_t)(i + 1));
                for (size_t k = 0; k < want; k++)
                    re_panel_text(&r.t, &p[i], "body line");
                if (want > tallest)
                    tallest = want;
            }
            re_tui_compose(&r.t, p, np);
            const char *s = out_of(&r);
            unsigned lines = 0;
            while (*s) {
                size_t len = 0;
                while (s[len] && s[len] != '\n')
                    len++;
                RE_CHECK_EQ_U(re_tui_cols_span(s, len), kWidths[w]);
                lines++;
                s += len;
                if (*s == '\n')
                    s++;
            }
            // One top border, the tallest body, one bottom border.
            RE_CHECK_EQ_U(lines, tallest + 2);
        }
    }
}

// The ascii fallback must produce the same geometry. A box drawn with plus and minus
// is uglier but it has to line up, or the fallback is not a fallback.
static void test_ascii_fallback(re_arena_t *a) {
    rig_t r;
    re_panel_t p;
    rig_init(&r, a, 60, false, false);
    re_panel_init(&p, a, "T", 1);
    re_panel_text(&r.t, &p, "hello");
    re_tui_compose(&r.t, &p, 1);
    const char *s = out_of(&r);
    RE_CHECK(strchr(s, '+') != NULL);
    RE_CHECK(strchr(s, '\xe2') == NULL); // no UTF-8 leaked into the ascii path
    while (*s) {
        size_t len = 0;
        while (s[len] && s[len] != '\n')
            len++;
        RE_CHECK_EQ_U(re_tui_cols_span(s, len), 60);
        s += len;
        if (*s == '\n')
            s++;
    }
}

// Colour is the difference between a report and a wall of escapes, so it has to be
// absent when it is not asked for, and every style has to close itself. The styled
// text lands in the panel body, because a panel is filled before it is composed.
static void test_color(re_arena_t *a) {
    rig_t r;
    re_panel_t p;
    rig_init(&r, a, 60, false, true);
    re_panel_init(&p, a, "T", 1);
    re_panel_kv(&r.t, &p, "key", "val", RE_ST_GOOD);
    RE_CHECK(strchr(p.body.p, '\x1b') == NULL);
    rig_init(&r, a, 60, true, true);
    re_panel_init(&p, a, "T", 1);
    re_panel_kv(&r.t, &p, "key", "val", RE_ST_GOOD);
    const char *body = p.body.p ? p.body.p : "";
    RE_CHECK(strstr(body, "val") != NULL);
    RE_CHECK(strstr(body, "\x1b[0m") != NULL);
    // The visible text survives styling: the escapes are not part of the content, so
    // the words a reader searches for are still there, in order.
    RE_CHECK(strstr(body, "key") < strstr(body, "val"));
}

// The display width of a composed line, ignoring the escapes. They are zero width by
// definition, so measuring them would say the box is far wider than the terminal and
// every assertion about geometry would be meaningless once colour is on. The content is
// stripped first and then measured, because the box characters are three bytes each and
// counting bytes would over-report the width threefold.
static size_t visible_cols(const char *s, size_t len) {
    char plain[256];
    size_t n = 0;
    for (size_t i = 0; i < len && n + 1 < sizeof(plain);) {
        if (s[i] == '\x1b') {
            while (i < len && s[i] != 'm')
                i++;
            if (i < len)
                i++;
            continue;
        }
        plain[n++] = s[i++];
    }
    plain[n] = '\0';
    return re_tui_cols_span(plain, n);
}

// A styled report has to be exactly as wide as an unstyled one. This is the case
// where a colour implementation quietly breaks the layout, and it cannot be seen in
// the plain text path at all.
static void test_styled_geometry(re_arena_t *a) {
    rig_t r;
    re_panel_t p;
    rig_init(&r, a, 72, true, true);
    re_panel_init(&p, a, "Keys", 1);
    re_panel_kv(&r.t, &p, "format", "pe", RE_ST_GOOD);
    re_panel_kv(&r.t, &p, "arch", "x86-64", RE_ST_ACCENT);
    re_tui_compose(&r.t, &p, 1);
    const char *s = out_of(&r);
    while (*s) {
        size_t len = 0;
        while (s[len] && s[len] != '\n')
            len++;
        RE_CHECK_EQ_U(visible_cols(s, len), 72);
        s += len;
        if (*s == '\n')
            s++;
    }
}

static void test_env(void) {
    // The environment is consulted, not cached, so a test can set it and clear it.
    // The convention is that the variable being present at all is what counts, which
    // is why an empty value is used to clear one here rather than deleting the name.
    _putenv("NO_COLOR=1");
    RE_CHECK(!re_tui_want_color());
    _putenv("NO_COLOR=");
    RE_CHECK(re_tui_want_color());
    _putenv("RE_TUI_ASCII=1");
    RE_CHECK(!re_tui_want_unicode());
    _putenv("RE_TUI_ASCII=");
    // With no terminal and no override, the answer is no: this suite runs under a pipe,
    // and claiming the box characters would be a lie about where the output is going.
    RE_CHECK(!re_tui_want_unicode());
    // The override exists for exactly the case the automatic answer cannot cover, which
    // is a console that reports a code page it does not actually use.
    _putenv("RE_TUI_UNICODE=1");
    RE_CHECK(re_tui_want_unicode());
    _putenv("RE_TUI_UNICODE=");
    // A pipe is never a terminal, whatever the overrides say about the encoding.
    RE_CHECK(!re_tui_console_utf8());
    _putenv("COLUMNS=100");
    RE_CHECK_EQ_U(re_tui_term_width(), 100);
    _putenv("COLUMNS=5");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
    _putenv("COLUMNS=1000");
    RE_CHECK_EQ_U(re_tui_term_width(), 200);
    _putenv("COLUMNS=");
    RE_CHECK_EQ_U(re_tui_term_width(), RE_TUI_DEFAULT_WIDTH);
}

// The header bar is inverted across its whole width, so the padding has to be inside
// the styled run. A bar that inverts only the text is the classic half done look.
static void test_header(re_arena_t *a) {
    rig_t r;
    rig_init(&r, a, 40, false, true);
    re_tui_header(&r.t, "left", "right");
    // The trailing newline is not part of the bar, so the text is compared whole.
    CHECK_STR(out_of(&r), "left                               right\n");
    rig_init(&r, a, 40, true, true);
    re_tui_header(&r.t, "left", "right");
    const char *s = out_of(&r);
    // The opening escape comes before the padding, and the reset after the right text.
    RE_CHECK(strstr(s, "\x1b[1;7m") < strstr(s, "right"));
    RE_CHECK(strstr(s, "right") < strstr(s, "\x1b[0m"));
    // A subject and a summary longer than the width must not underflow the padding
    // arithmetic into an enormous unsigned value and emit gigabytes of spaces.
    rig_init(&r, a, 40, false, true);
    re_tui_header(&r.t, "a very long subject indeed", "and a long summary too");
    s = out_of(&r);
    size_t len = 0;
    while (s[len] && s[len] != '\n')
        len++;
    RE_CHECK_EQ_U(re_tui_cols_span(s, len), re_tui_cols("a very long subject indeed") + 1 +
                                                re_tui_cols("and a long summary too"));
}
int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    test_cols();
    test_clip(&a);
    test_compose_even(&a);
    test_ascii_fallback(&a);
    test_color(&a);
    test_env();
    test_styled_geometry(&a);
    test_header(&a);
    re_arena_free(&a);
    return re_test_report("tui");
}
