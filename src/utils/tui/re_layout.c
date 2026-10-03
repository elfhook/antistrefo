// re_layout.c - composes the reference screen arrangement out of a description.
// Module: util (C11).
// Owns: re_layout_compose, which fixes the band order and the splitter position.
// Depends: re_screen.h, re_strbuf. Owns no data of its own and reads no input.
//           The arrangement is expressed, not hard coded per report, so a different
//           report can reuse it by filling the struct differently.
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"

// The band order, top to bottom. Written out once as constants rather than as a
// chain of offsets, because the whole point of the arrangement is that it is
// readable: a reader should be able to see the bands and their order in one screen
// of source instead of reverse engineering a pile of arithmetic.
#define BAND_TITLE 0u   // the subject, centred
#define BAND_TOOLBAR 1u // the row of controls
#define BAND_NAV 2u     // position, with a handle
#define BAND_LEGEND 3u  // what the shapes in the body mean
#define BAND_BODY 4u    // everything below the legend, to the status line
#define BAND_STATUS 5u  // the caret, at the very bottom

// Fixed heights. The title and legend are one row each because there is nothing to
// gain from more and everything to lose: they are labels, and a label that wraps is
// a label that has stopped being a label. The body takes the rest.
#define H_TITLE 1u
#define H_TOOLBAR 1u
#define H_NAV 1u
#define H_LEGEND 1u
#define H_STATUS 1u

// The split is a proportion rather than a column count, because a fixed left column
// that is right on an 80 column terminal is most of the screen on a 200 column one,
// and wrong in the other direction on a 60. A proportion of the available width is
// the only thing that survives both, so the clamp is expressed the same way.
#define SPLIT_MIN 18u
#define SPLIT_MAX_FRAC 45u // percent of the body width, so the code pane never vanishes

static uint16_t left_width(uint16_t total, uint16_t want) {
    if (want < SPLIT_MIN)
        want = SPLIT_MIN;
    uint16_t cap = (uint16_t)((total * SPLIT_MAX_FRAC) / 100u);
    if (cap < SPLIT_MIN)
        cap = SPLIT_MIN;
    if (want > cap)
        want = cap;
    if (total > SPLIT_MIN + 12u && want > total - 12u)
        want = (uint16_t)(total - 12u);
    return want;
}

// The left pane: a framed list with a heading and one selected row. Its own function
// because it is the only part of the body that depends on the split, and splitting
// the two apart is what keeps the composition readable.
static void draw_left(re_screen_t *s, const re_layout_t *L, uint16_t y, uint16_t h, uint16_t w) {
    re_screen_box(s, y, 0, w, h, L->list_title, (uint8_t)RE_ST_NONE);
    if (h > 2u)
        re_screen_list(s, (uint16_t)(y + 1u), 1, (uint16_t)(w - 2u), (uint16_t)(h - 1u),
                       L->list_head, L->rows, L->n_rows, L->sel_row);
}

// The right pane: a tab strip over a numbered code view with a scrollbar. Returns
// nothing because a pane that cannot fit is simply not drawn: there is no fallback
// that is better than an empty pane, and pretending otherwise hides a real problem.
static void draw_right(re_screen_t *s, const re_layout_t *L, uint16_t y, uint16_t h, uint16_t x,
                       uint16_t w, uint16_t screen_w) {
    re_screen_tabs(s, y, x, w, L->tabs, L->n_tabs, L->active_tab);
    re_screen_hline(s, (uint16_t)(y + 1u), x, w, "\xe2\x94\x80", (uint8_t)RE_ST_NONE);
    uint16_t code_y = (uint16_t)(y + 2u);
    uint16_t code_h = (uint16_t)(h - 2u);
    if (!code_h || w <= 10u)
        return;
    // The mark array is indexed against the code lines, so its count is the line
    // count: one byte per line saying whether that line carries a mark.
    re_screen_gutter(s, code_y, x, code_h, L->base_line, L->marks, L->n_code);
    re_screen_code(s, code_y, (uint16_t)(x + 9u), (uint16_t)(w - 10u), code_h, L->code, L->n_code,
                   L->base_line, L->marks);
    re_screen_vscroll(s, code_y, (uint16_t)(screen_w - 1u), code_h, (uint16_t)L->scroll_pos,
                      (uint16_t)L->scroll_total);
}
// A button: the label in brackets, with the padding drawn after the closing bracket so
// the whole thing carries one zone. The brackets are drawn last and belong to the zone,
// which is what makes a click on one a click on the button rather than on the space
// beside it.
static void draw_button(re_screen_t *s, uint16_t y, uint16_t x, const char *label, uint8_t style,
                        uint8_t zone) {
    re_screen_put(s, y, x, "[", style, zone);
    re_screen_put_run(s, y, (uint16_t)(x + 1u), (uint16_t)(x + 1u + RE_TUI_MIN_WIDTH), label, style,
                      zone);
    size_t n = re_tui_cols(label);
    re_screen_put(s, y, (uint16_t)(x + 1u + n), "]", style, zone);
    re_screen_fill(s, y, (uint16_t)(x + 2u + n), 1, 1, " ", style, zone);
}

// The body before a file is open: one framed box, the message, and the one control
// that does anything.
//
// Both are placed by a single helper rather than by arithmetic at each call site, so
// there is one answer to "where does a centred run start" and it is checkable on its
// own. A box this size has one thing in it and no need to scan, so a fixed indent would
// do; centring is because a lone control under a lone line reads as a question, and a
// question wants to be in the middle.
static void centred(re_screen_t *s, uint16_t y, uint16_t width, const char *text, uint8_t style,
                    uint8_t zone) {
    size_t n = re_tui_cols(text);
    if (!n || n + 2u >= width)
        return;
    uint16_t x = (uint16_t)(1u + (width - n) / 2u);
    re_screen_put_run(s, y, x, (uint16_t)(1u + width), text, style, zone);
}

static uint16_t draw_welcome(re_screen_t *s, re_layout_t *L, uint16_t y, uint16_t h, uint16_t w) {
    if (h < 5u || w < 24u)
        return 0;
    re_screen_box(s, y, 0, w, h, "Get started", (uint8_t)RE_ST_NONE);
    uint16_t inner_w = (uint16_t)(w - 2u);
    centred(s, (uint16_t)(y + 2u), inner_w, L->welcome ? L->welcome : "", (uint8_t)RE_ST_NONE,
            RE_SCREEN_ZONE_NONE);

    const char *label = L->button ? L->button : "Load";
    size_t bc = re_tui_cols(label) + 3u;
    char btn[32];
    size_t k = 0;
    btn[k++] = '[';
    for (size_t i = 0; label[i] && k + 2u < sizeof(btn); i++)
        btn[k++] = label[i];
    btn[k++] = ']';
    btn[k] = '\0';
    L->button_zone = re_screen_zone(s);
    centred(s, (uint16_t)(y + 4u), inner_w, btn, (uint8_t)RE_ST_ACCENT, L->button_zone);
    (void)bc;
    return h;
}

uint16_t re_layout_compose(re_screen_t *s, re_layout_t *L) {
    if (!s->cell || !L)
        return 0;
    if (s->rows < BAND_BODY + 2u) {
        // Too short for the arrangement to mean anything. One line of the subject is
        // the most that can be said honestly, so that is what is drawn.
        re_screen_put_run(s, 0, 0, s->cols, L->file ? L->file : "", (uint8_t)RE_ST_TITLE,
                          RE_SCREEN_ZONE_NONE);
        return 0;
    }
    re_screen_clear(s);

    uint16_t w = s->cols;
    uint16_t top = BAND_TITLE;
    uint16_t body_y = (uint16_t)(BAND_BODY + 1u);

    // Title, centred the way a window title is: the subject alone on its own row.
    if (L->file && *L->file && w > 2) {
        size_t fc = re_tui_cols(L->file);
        uint16_t fx = fc + 1 < w ? (uint16_t)((w - fc) / 2u) : 1;
        re_screen_put_run(s, top, fx, w, L->file, (uint8_t)RE_ST_TITLE, RE_SCREEN_ZONE_NONE);
    }
    re_screen_toolbar(s, (uint16_t)(top + H_TITLE), L->toolbar, L->n_toolbar);
    re_screen_nav(s, (uint16_t)(top + H_TITLE + H_TOOLBAR), 1, (uint16_t)(w - 2), L->nav_pos,
                  L->nav_total);
    re_screen_legend(s, (uint16_t)(top + H_TITLE + H_TOOLBAR + H_NAV), 1, (uint16_t)(w - 2),
                     L->legend, L->n_legend);

    uint16_t body_h = (uint16_t)(s->rows - body_y - H_STATUS);
    if (!body_h)
        return 0;

    uint16_t left_w = left_width(w, L->left_w);
    if (L->welcome) {
        // No file yet: one box, and none of the panes. The button's zone is recorded so
        // a click on it can be told from a click anywhere else.
        L->button_zone = RE_SCREEN_ZONE_NONE;
        draw_welcome(s, L, body_y, body_h, w);
        re_screen_status(s, (uint16_t)(s->rows - H_STATUS), 0, w, L->status, L->caret);
        return body_h;
    }
    if (left_w + 2u >= w)
        left_w = (uint16_t)((w > 4u) ? w / 3u : 0u);
    draw_left(s, L, body_y, body_h, left_w);

    // The gap between the panes carries the splitter. It is drawn as one column of
    // dots rather than a frame, so it reads as something that can be dragged rather
    // than as content.
    uint16_t gap_x = left_w;
    re_screen_vline(s, body_y, gap_x, body_h, "\xe2\x94\x86", (uint8_t)RE_ST_NONE);
    draw_right(s, L, body_y, body_h, (uint16_t)(gap_x + 1u), (uint16_t)(w - gap_x - 1u), w);

    uint16_t st_y = (uint16_t)(s->rows - H_STATUS);
    re_screen_status(s, st_y, 0, w, L->status, L->caret);
    return body_h;
}
