// test_input.c - the decoder, the focus order, and the frame diff.
// Module: test (C11).
// Owns: the assertions for cli/screen. Exercises no terminal and reads no input.
// Depends: re_test, re_arena, re_strbuf, re_input, re_focus, re_draw, re_screen.
#include "re_test.h"

#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_screen.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_input.h"

#include <string.h>

int re_test_count = 0;
int re_test_fail = 0;

static void feed(re_input_t *in, const char *s) {
    re_input_feed(in, (const uint8_t *)s, strlen(s));
}

// A plain character is itself, and is not mistaken for a sequence introducer.
static void test_plain_keys(void) {
    re_input_t in;
    re_ev_t ev;
    re_input_init(&in);
    feed(&in, "aZ");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.kind, RE_EV_KEY);
    RE_CHECK_EQ_U(ev.key, 'a');
    RE_CHECK(!ev.ctrl);
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.key, 'Z');
    RE_CHECK(!re_input_next(&in, &ev));
}

// Enter, tab and backspace arrive as their own bytes on every terminal, and Ctrl is
// the letter minus a quarter. Getting either wrong breaks every binding at once.
static void test_control_keys(void) {
    re_input_t in;
    re_ev_t ev;
    re_input_init(&in);
    feed(&in, "\r\t\x7f");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.key, RE_KEY_ENTER);
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.key, RE_KEY_TAB);
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.key, RE_KEY_BACKSPACE);

    re_input_init(&in);
    feed(&in, "\x03");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK(ev.ctrl);
    RE_CHECK_EQ_U(ev.key, 3); // Ctrl-C is the number 3
}

// The arrow keys are the sequences every terminal sends, in both the CSI and the SS3
// spelling. A decoder that only knows one of them works on half the terminals.
static void test_arrows_both_spellings(void) {
    static const struct {
        const char *seq;
        uint32_t key;
    } kCases[] = {
        {"\x1b[A", RE_KEY_UP},      {"\x1b[B", RE_KEY_DOWN},  {"\x1b[C", RE_KEY_RIGHT},
        {"\x1b[D", RE_KEY_LEFT},    {"\x1bOA", RE_KEY_UP},    {"\x1bOD", RE_KEY_LEFT},
        {"\x1b[H", RE_KEY_HOME},    {"\x1b[F", RE_KEY_END},   {"\x1b[Z", RE_KEY_STAB},
        {"\x1b[3~", RE_KEY_DELETE}, {"\x1b[5~", RE_KEY_PGUP}, {"\x1b[6~", RE_KEY_PGDN},
    };
    for (size_t i = 0; i < sizeof(kCases) / sizeof(kCases[0]); i++) {
        re_input_t in;
        re_ev_t ev;
        re_input_init(&in);
        feed(&in, kCases[i].seq);
        RE_CHECK(re_input_next(&in, &ev));
        RE_CHECK_EQ_U(ev.key, kCases[i].key);
    }
}

// Half a sequence is not an event. This is the property that stops a paste arriving in
// two reads from turning into a screenful of arrow keys.
static void test_partial_sequence_is_not_an_event(void) {
    re_input_t in;
    re_ev_t ev;
    re_input_init(&in);
    feed(&in, "\x1b[");
    RE_CHECK(!re_input_next(&in, &ev));
    RE_CHECK_EQ_U(in.n, 2); // and nothing was consumed
    feed(&in, "A");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.key, RE_KEY_UP);
    RE_CHECK_EQ_U(in.n, 0);

    // A lone ESC is not yet an event either: the next byte may complete a sequence.
    re_input_init(&in);
    feed(&in, "\x1b");
    RE_CHECK(!re_input_next(&in, &ev));
}

// A sequence this decoder does not model is consumed and dropped, not turned into a
// key. A made up key would do something to the state; a dropped one does nothing.
static void test_unknown_sequence_is_dropped(void) {
    re_input_t in;
    re_ev_t ev;
    re_input_init(&in);
    feed(&in, "\x1b[200~x");
    // The bracketed paste start is not a key, and the x after it must still arrive.
    size_t produced = 0;
    uint32_t last = 0;
    while (re_input_next(&in, &ev)) {
        produced++;
        last = ev.key;
    }
    RE_CHECK_EQ_U(produced, 1);
    RE_CHECK_EQ_U(last, 'x');
}

// A mouse press reports the cell that was clicked, converted from the protocol's one
// based coordinates, and a release is distinguished from a press.
static void test_mouse_coordinates_are_zero_based(void) {
    re_input_t in;
    re_ev_t ev;
    re_input_init(&in);
    feed(&in, "\x1b[<0;11;4M");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.kind, RE_EV_MOUSE);
    RE_CHECK_EQ_U(ev.button, RE_MOUSE_LEFT);
    RE_CHECK(ev.press);
    RE_CHECK_EQ_U(ev.col, 10); // the protocol counts from one
    RE_CHECK_EQ_U(ev.row, 3);

    re_input_init(&in);
    feed(&in, "\x1b[<0;1;1m");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK(!ev.press);

    re_input_init(&in);
    feed(&in, "\x1b[<64;5;5M");
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.button, RE_MOUSE_WHEEL_UP);
    RE_CHECK_EQ_U(ev.kind, RE_EV_MOUSE);
}

// A character split across two reads is one key. A terminal that flushes mid character
// is normal, not a fault.
static void test_utf8_split_across_feeds(void) {
    re_input_t in;
    re_ev_t ev;
    re_input_init(&in);
    feed(&in, "\xe2\x96"); // two bytes of a three byte sequence
    RE_CHECK(!re_input_next(&in, &ev));
    feed(&in, "\x88"); // the last one
    RE_CHECK(re_input_next(&in, &ev));
    RE_CHECK_EQ_U(ev.key, 0x2588); // the full block
}

// Key names exist for a status bar, so a reader sees "Up" rather than a number.
static void test_key_names(void) {
    RE_CHECK(strcmp(re_input_key_name(RE_KEY_UP), "Up") == 0);
    RE_CHECK(strcmp(re_input_key_name(RE_KEY_PGDN), "PgDn") == 0);
    RE_CHECK(strcmp(re_input_key_name(RE_KEY_F1 + 4u), "F5") == 0);
    RE_CHECK(strcmp(re_input_key_name(0x1234567u), "?") == 0);
}

// The tab order is drawing order, ascending by id, and the cursor wraps at both ends.
static void test_focus_order_and_wrap(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 6, 30));
    re_screen_clear(&s);
    static const char *items[] = {"One", "Two", "Three"};
    re_screen_toolbar(&s, 0, items, 3);
    static const char *rows[] = {"alpha", "beta"};
    re_screen_list(&s, 2, 0, 20, 4, "Head", rows, 2, 0);
    re_focus_t f;
    re_focus_init(&f);
    re_focus_build(&f, &s);
    RE_CHECK_EQ_U(f.n, 5); // three toolbar items and two list rows
    RE_CHECK_EQ_U(f.zone, f.order[0]);
    RE_CHECK(re_focus_next(&f));
    RE_CHECK(!f.wrapped);
    RE_CHECK_EQ_U(f.at, 1);
    for (size_t i = 0; i < 4; i++)
        RE_CHECK(re_focus_next(&f));
    RE_CHECK(f.wrapped);
    RE_CHECK_EQ_U(f.at, 0); // wrapped from the end back to the start
    RE_CHECK(re_focus_prev(&f));
    RE_CHECK(f.wrapped);
    RE_CHECK_EQ_U(f.at, f.n - 1); // and backwards from the start to the end
}

// A click resolves through the grid, so no widget needs to know where it is. A click
// on empty space is not an error and must not move the cursor.
static void test_click_resolves_through_the_grid(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    RE_CHECK(re_screen_init(&s, a, &out, 6, 30));
    re_screen_clear(&s);
    static const char *items[] = {"One", "Two"};
    re_screen_toolbar(&s, 0, items, 2);
    re_focus_t f;
    re_focus_init(&f);
    re_focus_build(&f, &s);
    RE_CHECK_EQ_U(f.n, 2);

    uint8_t second = f.order[1];
    RE_CHECK(re_focus_click(&f, &s, 0, 9)); // inside the second item, not on the separator
    RE_CHECK_EQ_U(f.zone, second);

    // Empty space below the toolbar belongs to no control.
    RE_CHECK(!re_focus_click(&f, &s, 4, 20));
    RE_CHECK_EQ_U(f.zone, second); // and the cursor did not move
    // Outside the grid entirely.
    RE_CHECK(!re_focus_click(&f, &s, 99, 99));
    RE_CHECK_EQ_U(f.zone, second);
}

// Rebuilding after a layout change keeps the focused control focused, by id rather
// than by position, so a control appearing above it does not steal the cursor.
static void test_focus_survives_rebuild(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_screen_t s;
    re_focus_t f;
    re_focus_init(&f);
    RE_CHECK(re_screen_init(&s, a, &out, 6, 30));
    re_screen_clear(&s);
    static const char *items[] = {"One", "Two", "Three"};
    re_screen_toolbar(&s, 0, items, 3);
    re_focus_build(&f, &s);
    RE_CHECK(re_focus_next(&f));
    RE_CHECK(re_focus_next(&f));
    uint8_t was = f.zone;

    RE_CHECK(re_screen_init(&s, a, &out, 6, 30));
    re_screen_clear(&s);
    static const char *more[] = {"Zero", "One", "Two", "Three"};
    re_screen_toolbar(&s, 0, more, 4);
    re_focus_build(&f, &s);
    RE_CHECK_EQ_U(f.n, 4);
    RE_CHECK_EQ_U(f.zone, was); // the same control, wherever it landed
}

// The diff writes a whole frame the first time and nothing at all when nothing moved.
static void test_diff_writes_nothing_when_unchanged(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_draw_t d;
    RE_CHECK(re_draw_init(&d, a, 6, 20));
    re_screen_t cur;
    RE_CHECK(re_screen_init(&cur, a, &out, 6, 20));
    re_screen_clear(&cur);
    re_screen_put_run(&cur, 0, 0, 20, "hello", RE_ST_NONE, RE_SCREEN_ZONE_NONE);

    re_draw_full(&d, &cur);
    RE_CHECK(d.out.len > 0);
    // The first paint clears the screen and then writes only the cells that are not
    // already blank, because a cleared cell and a blank previous cell are the same.
    RE_CHECK(strstr(d.out.p, "\x1b[2J") != NULL);
    uint32_t first = d.cells;
    RE_CHECK_EQ_U(first, 5); // the five letters of hello

    // The same frame again costs nothing. This is the whole reason for the diff.
    re_draw_frame(&d, &cur);
    RE_CHECK_EQ_U(d.cells, 0);
    RE_CHECK_EQ_U(d.out.len, 0);

    // One changed cell costs one cell, not a repaint.
    re_screen_put_run(&cur, 2, 3, 20, "X", RE_ST_NONE, RE_SCREEN_ZONE_NONE);
    re_draw_frame(&d, &cur);
    RE_CHECK_EQ_U(d.cells, 1);
    RE_CHECK(d.out.len > 0);
}

// A resize cannot be diffed against, so it becomes a full repaint rather than a patch
// computed from two grids of different shapes.
static void test_resize_forces_full_repaint(re_arena_t *a) {
    re_strbuf_t out;
    re_strbuf_init(&out, a);
    re_draw_t d;
    RE_CHECK(re_draw_init(&d, a, 4, 10));
    re_screen_t cur;
    RE_CHECK(re_screen_init(&cur, a, &out, 4, 10));
    re_screen_clear(&cur);
    re_draw_full(&d, &cur);
    RE_CHECK(d.valid);

    RE_CHECK(re_draw_resize(&d, a, 8, 20));
    RE_CHECK(!d.valid); // invalidated, so the next frame is a full one
    RE_CHECK(re_screen_init(&cur, a, &out, 8, 20));
    re_screen_clear(&cur);
    re_draw_frame(&d, &cur);
    // Nothing is drawn, so nothing differs from the cleared frame: the repaint
    // is the clear itself.
    RE_CHECK(strstr(d.out.p, "\x1b[2J") != NULL);
    RE_CHECK_EQ_U(d.cells, 0);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    test_plain_keys();
    test_control_keys();
    test_arrows_both_spellings();
    test_partial_sequence_is_not_an_event();
    test_unknown_sequence_is_dropped();
    test_mouse_coordinates_are_zero_based();
    test_utf8_split_across_feeds();
    test_key_names();
    test_focus_order_and_wrap(&a);
    test_click_resolves_through_the_grid(&a);
    test_focus_survives_rebuild(&a);
    test_diff_writes_nothing_when_unchanged(&a);
    test_resize_forces_full_repaint(&a);
    re_arena_free(&a);
    return re_test_report("input");
}
