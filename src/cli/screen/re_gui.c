// re_gui.c - the interactive view over an analysed file.
// Module: cli (C11).
// Owns: the loop, the selection, and the mapping from keys to state.
// Depends: re_gui.h, re_term, re_input, re_focus, re_draw, re_screen, re_layout,
//           re_analysis, re_code. Decoding and rendering are the shared backend's
//           job, reached the same way every other command reaches them.
#include "cli/screen/re_gui.h"

#include "features/analysis/re_analyze.h"
#include "features/code/re_code.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_input.h"
#include "cli/screen/re_term.h"

#include <stdio.h>
#include <string.h>

// How much a listing holds at once. Bounded rather than sized to the file, because a
// pane has a fixed number of rows and a function can be longer than any of them.
#define CODE_MAX 48u
#define LIST_MAX 256u
#define LIST_ROWS 24u

typedef struct {
    re_analysis_t an;
    re_term_t term;
    re_draw_t draw;
    re_focus_t focus;
    size_t sel; // the selected function
    size_t tab; // the showing pane
    bool mouse; // mouse reporting is on, so the status may say "click"
    bool quit;
} gui_t;

// The listing for the selected function, rebuilt each frame. The buffers live in the
// arena and are reused, so a frame costs no allocation and the pointer array handed to
// the widget stays valid for exactly as long as the frame does.
typedef struct {
    re_strbuf_t line[CODE_MAX];
    const char *text[CODE_MAX];
    uint8_t mark[CODE_MAX];
    size_t n;
    uint32_t base;
    size_t vis;
} listing_t;

typedef struct {
    char *name[LIST_MAX];
    char addr[LIST_MAX][20];
    size_t n;
    size_t vis;
} funcs_t;

static void funcs_fill(funcs_t *l, re_arena_t *a, const re_analysis_t *an) {
    l->n = 0;
    size_t total = RE_VEC_LEN(&an->scan.funcs);
    for (size_t i = 0; i < total && l->n < LIST_MAX; i++) {
        const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        re_strbuf_t sb;
        re_strbuf_init(&sb, a);
        re_strbuf_put_hex64(&sb, f->va, 16);
        re_strbuf_putc(&sb, 0);
        size_t n = sb.len < 19u ? sb.len : 19u;
        for (size_t k = 0; k < n; k++)
            l->addr[l->n][k] = sb.p[k];
        l->addr[l->n][n] = '\0';
        // A function with no name has one invented from its address, so the list never
        // shows a blank row that cannot be told apart from any other blank row.
        re_strbuf_t fb;
        re_strbuf_init(&fb, a);
        re_strbuf_puts(&fb, "sub_");
        re_strbuf_put_hex64(&fb, f->va, 16);
        re_strbuf_putc(&fb, 0);
        const char *nm = (f->name.p && f->name.n) ? f->name.p : fb.p;
        l->name[l->n] = re_arena_strdup(a, nm);
        l->n++;
    }
    l->vis = LIST_ROWS;
    if (l->vis > l->n)
        l->vis = l->n;
}

// Decode the selected function into text, using the shared decoder and the shared
// renderer. This is the same pair the disasm command uses, so what the view shows and
// what a report says about the same address cannot disagree.
static void listing_fill(listing_t *ls, re_arena_t *a, const re_analysis_t *an, size_t sel,
                         size_t vis) {
    ls->n = 0;
    ls->base = 0;
    for (size_t i = 0; i < CODE_MAX; i++)
        re_strbuf_init(&ls->line[i], a);
    if (sel >= RE_VEC_LEN(&an->scan.funcs))
        return;
    const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, sel);
    ls->base = (uint32_t)f->va;
    if (!an->code.dis)
        return;
    uint64_t end = f->va + (f->size ? f->size : 1u);
    for (uint64_t va = f->va; va < end && ls->n < CODE_MAX;) {
        re_insn_t in;
        if (!re_code_insn(&an->code, va, &in))
            break;
        re_strbuf_clear(&ls->line[ls->n]);
        an->code.dis->render(an->code.dis->ctx, &in, a, &ls->line[ls->n]);
        // A line the reader can act on gets a mark: a branch is where the flow goes,
        // and that is the one thing worth noticing without reading every line.
        ls->mark[ls->n] = (uint8_t)(in.is_call || in.is_branch);
        ls->text[ls->n] = ls->line[ls->n].p ? ls->line[ls->n].p : "";
        ls->n++;
        if (!in.size)
            break; // a zero length instruction would loop for ever
        va += in.size;
    }
    (void)vis;
}

// The window of function names the list shows, kept centred on the selection so the
// reader always sees what they moved to.
static void funcs_window(const gui_t *g, const funcs_t *l, const char **rows) {
    size_t half = l->vis > 2u ? l->vis / 2u : 0u;
    for (size_t i = 0; i < l->vis; i++) {
        size_t idx = (g->sel >= half ? g->sel - half : 0u) + i;
        if (l->n && idx >= l->n)
            idx = l->n - 1u;
        rows[i] = l->n ? l->name[idx] : "(no functions)";
    }
}

static void compose(re_screen_t *s, gui_t *g, const funcs_t *l, const listing_t *ls) {
    static const char *kTabs[] = {"Disasm", "Pseudocode", "Hex", "Imports", "Exports"};
    static const char *kToolbar[] = {"Open", "Save", "Graph", "Strngs", "Xrefs", "Help"};
    static const char *kLegend[] = {"code", "branch", "gap", "selected"};

    const char *lrows[LIST_ROWS];
    funcs_window(g, l, lrows);

    char status[80];
    snprintf(status, sizeof(status), "%u functions", (unsigned)l->n);

    re_layout_t L = {0};
    L.file = g->an.path.p ? g->an.path.p : "antistrefo";
    L.toolbar = kToolbar;
    L.n_toolbar = 6;
    L.nav_pos = g->sel;
    L.nav_total = l->n;
    L.legend = kLegend;
    L.n_legend = 4;
    L.list_title = "Functions";
    L.list_head = "Name";
    L.rows = lrows;
    L.n_rows = l->vis ? l->vis : 1u;
    L.sel_row = l->vis > 1u ? l->vis / 2u : 0u;
    L.tabs = kTabs;
    L.n_tabs = 5;
    L.active_tab = g->tab;
    L.code = ls->text;
    L.n_code = ls->n;
    L.base_line = ls->base;
    L.marks = ls->mark;
    L.scroll_pos = 0;
    L.scroll_total = ls->n ? ls->n : 1u;
    L.status = status;
    L.caret = g->mouse ? "click or Tab; Enter opens; q quits" : "arrows move; q quits";
    L.left_w = 30;
    re_layout_compose(s, &L);
    re_focus_build(&g->focus, s);
}

static void apply(gui_t *g, const re_ev_t *ev) {
    if (ev->kind == RE_EV_KEY) {
        switch (ev->key) {
            case 'q':
            case 'Q':
            case RE_KEY_ESCAPE:
                g->quit = true;
                return;
            case RE_KEY_UP:
                if (g->sel)
                    g->sel--;
                return;
            case RE_KEY_DOWN:
                g->sel++;
                return;
            case RE_KEY_PGUP:
                g->sel = g->sel > 16u ? g->sel - 16u : 0u;
                return;
            case RE_KEY_PGDN:
                g->sel += 16u;
                return;
            case RE_KEY_HOME:
                g->sel = 0;
                return;
            case RE_KEY_TAB:
                re_focus_next(&g->focus);
                return;
            case RE_KEY_STAB:
                re_focus_prev(&g->focus);
                return;
            case RE_KEY_LEFT:
                if (g->tab)
                    g->tab--;
                return;
            case RE_KEY_RIGHT:
                g->tab++;
                return;
            default:
                return;
        }
    }
    if (ev->kind == RE_EV_MOUSE && ev->press) {
        // The click is already resolved against the grid by the caller, so all that is
        // left here is to let the wheel move. A click that hit a control has moved the
        // focus and nothing else; what it activates is a later decision.
        return;
    }
}

// One turn of the loop: compose, paint, wait. Returns false to leave.
static bool turn(gui_t *g, re_arena_t *a, re_screen_t *frame, funcs_t *list, listing_t *ls) {
    if (list->n && g->sel >= list->n)
        g->sel = list->n - 1u;
    listing_fill(ls, a, &g->an, g->sel, list->vis);
    compose(frame, g, list, ls);
    re_draw_full(&g->draw, frame);
    re_draw_home(&g->draw, 0, 0);
    re_term_write(&g->term, g->draw.out.p, g->draw.out.len);

    re_ev_t ev;
    if (!re_term_wait(&g->term, &ev, 250u)) {
        // No key. Ask the terminal for its size anyway, because a resize is not always
        // an event on every terminal, and a stale frame size wraps every row.
        uint16_t nr = 0, nc = 0;
        re_term_size(&nr, &nc);
        if (nr != frame->rows || nc != frame->cols)
            return re_draw_resize(&g->draw, a, nr, nc) &&
                   re_screen_init(frame, a, &g->draw.out, nr, nc);
        return true;
    }
    if (ev.kind == RE_EV_RESIZE) {
        uint16_t nr = 0, nc = 0;
        re_term_size(&nr, &nc);
        return re_draw_resize(&g->draw, a, nr, nc) &&
               re_screen_init(frame, a, &g->draw.out, nr, nc);
    }
    if (ev.kind == RE_EV_MOUSE && ev.press)
        // A click that landed on a control moved the focus. One that did not is
        // nothing, which is right for a stray click in the body.
        (void)re_focus_click(&g->focus, frame, ev.row, ev.col);
    apply(g, &ev);
    return !g->quit;
}

int re_cmd_gui(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    (void)ctx;
    if (!path || !*path) {
        fprintf(stderr, "gui needs a file\n");
        return 2;
    }
    gui_t g;
    memset(&g, 0, sizeof(g));
    re_arena_t arena;
    re_arena_init(&arena, 1u << 23);

    // The terminal is taken before the file is analysed. The other order puts a full
    // screen session up and then prints a failure into it, which leaves the reader with
    // escape sequences and no way back.
    if (!re_term_open(&g.term, true)) {
        fprintf(stderr, "gui needs a terminal on both ends; try the report commands\n");
        re_arena_free(&arena);
        return 2;
    }
    g.mouse = re_term_has_mouse(&g.term);

    bool ready = re_analysis_open(&g.an, &arena, path);
    uint16_t rows = 24, cols = 80;
    re_term_size(&rows, &cols);
    bool have_draw = re_draw_init(&g.draw, &arena, rows, cols);
    re_screen_t frame;
    bool have_frame = re_screen_init(&frame, &arena, &g.draw.out, rows, cols);
    re_focus_init(&g.focus);
    funcs_t list;
    memset(&list, 0, sizeof(list));
    listing_t ls;
    memset(&ls, 0, sizeof(ls));
    if (ready && have_draw && have_frame) {
        funcs_fill(&list, &arena, &g.an);
        while (turn(&g, &arena, &frame, &list, &ls))
            ;
    }
    re_term_close(&g.term);
    if (ready)
        re_analysis_close(&g.an);
    re_arena_free(&arena);
    return ready ? 0 : 2;
}
