// re_gui.c - the interactive view over an analysed file.
// Module: cli (C11).
// Owns: the loop, the selection, and the mapping from keys to state.
// Depends: re_gui.h, re_term, re_input, re_focus, re_draw, re_screen, re_layout,
//           re_analysis, re_code. Decoding and rendering are the shared backend's
//           job, reached the same way every other command reaches them.
#include "cli/screen/re_gui.h"

#include "features/analysis/re_analyze.h"
#include "features/code/re_code.h"
#include "features/code/re_stack.h"
#include "features/dec/re_decompile.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_input.h"
#include "cli/screen/re_pseudocode.h"
#include "cli/screen/re_term.h"

#include <stdio.h>
#include <string.h>

// How much a listing holds at once. Bounded rather than sized to the file, because a
// pane has a fixed number of rows and a function can be longer than any of them.
#define CODE_MAX 48u
#define LIST_MAX 256u
#define LIST_ROWS 24u

// The panes that exist. Two, not five: a tab that opens onto "not in this build" is a
// promise the tool does not keep, so the strip grows when the panes do.
#define RE_TAB_COUNT 2u

typedef struct {
    re_analysis_t an;
    re_term_t term;
    re_draw_t draw;
    re_focus_t focus;
    size_t sel; // the selected function
    size_t tab; // 0 disassembly, 1 pseudocode
    bool mouse; // mouse reporting is on, so the status may say "click"
    bool quit;
    // What the right pane shows, decided once per turn by the active tab and filled in
    // by whichever pass produced it. Keeping it here rather than in compose is what
    // lets the layout stay ignorant of where its text came from.
    const char **body;
    const uint8_t *body_marks;
    size_t body_n;
    uint32_t body_base;
    const char *body_note;
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

// The decompiled body, kept across turns. Decompiling walks and lowers the whole
// function, so doing it on every frame would be doing the same work sixty times a
// second to produce the same text. It is built once per selected function and reused
// until the selection moves.
typedef struct {
    re_strbuf_t buf;
    const char *line[RE_PSEUDO_MAX];
    uint8_t mark[RE_PSEUDO_MAX];
    size_t n;
    size_t built_for;
    bool started;
    bool ok;
} pseudo_t;

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
// Split the emitted body into lines. The buffer is left intact and the lines are
// pointers into it, so this is a walk rather than a copy, and the pointers stay valid
// until the next build of the same function.
static void pseudo_split(pseudo_t *ps) {
    re_strbuf_putc(&ps->buf, 0);
    ps->n = re_pseudo_split(ps->buf.p, ps->line, ps->mark, RE_PSEUDO_MAX);
}

// The decompiled body for the selected function, built once and reused. Refusing to
// decompile is the case worth being careful about: an empty pane reads as "this
// function does nothing", which is a different and wrong claim.
static void pseudo_fill(pseudo_t *ps, re_arena_t *a, re_analysis_t *an, size_t sel) {
    if (!ps->started) {
        re_strbuf_init(&ps->buf, a);
        ps->started = true;
        ps->built_for = (size_t)-1;
    }
    if (ps->built_for == sel)
        return;
    ps->built_for = sel;
    re_strbuf_clear(&ps->buf);
    ps->n = 0;
    if (sel >= RE_VEC_LEN(&an->scan.funcs))
        return;
    const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, sel);
    re_decomp_t d;
    d.code = &an->code;
    // The xref set is what turns a call target into a name; without it every call
    // prints as a bare address.
    d.xrefs = &an->xs;
    d.arena = a;
    re_stack_t st;
    re_stack_analyze(d.code, f, a, &st);
    ps->ok = re_decompile_ok(&d, f);
    if (ps->ok)
        re_decompile_func(&d, f, &st, &ps->buf);
    pseudo_split(ps);
    if (!ps->n) {
        ps->line[0] = "// this body did not lower: no instruction was recovered from it";
        ps->mark[0] = 1;
        ps->n = 1;
    }
}

// The right pane's content for the active tab. The disassembly is rebuilt every turn
// because it is cheap and should follow the selection exactly; the pseudocode is not,
// and saying so is why the two take different paths.
static void body_for(gui_t *g, re_arena_t *a, listing_t *ls, pseudo_t *ps, size_t sel) {
    if (g->tab == 1) {
        pseudo_fill(ps, a, &g->an, sel);
        g->body = ps->line;
        g->body_marks = ps->mark;
        g->body_n = ps->n;
        g->body_base = 0;
        g->body_note = NULL;
        return;
    }
    listing_fill(ls, a, &g->an, sel, ls->vis);
    g->body = ls->text;
    g->body_marks = ls->mark;
    g->body_n = ls->n;
    g->body_base = ls->base;
    g->body_note = NULL;
}

static void funcs_window(const gui_t *g, const funcs_t *l, const char **rows) {
    size_t half = l->vis > 2u ? l->vis / 2u : 0u;
    for (size_t i = 0; i < l->vis; i++) {
        size_t idx = (g->sel >= half ? g->sel - half : 0u) + i;
        if (l->n && idx >= l->n)
            idx = l->n - 1u;
        rows[i] = l->n ? l->name[idx] : "(no functions)";
    }
}
static void compose(re_screen_t *s, gui_t *g, const funcs_t *l) {
    static const char *kTabs[RE_TAB_COUNT] = {"Disasm", "Pseudocode"};
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
    L.n_tabs = RE_TAB_COUNT;
    L.active_tab = g->tab;
    L.code = g->body;
    L.n_code = g->body_n;
    L.base_line = g->body_base;
    L.marks = g->body_marks;
    L.scroll_pos = 0;
    L.scroll_total = g->body_n ? g->body_n : 1u;
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
static bool turn(gui_t *g, re_arena_t *a, re_screen_t *frame, funcs_t *list, listing_t *ls,
                 pseudo_t *ps) {
    if (list->n && g->sel >= list->n)
        g->sel = list->n - 1u;
    body_for(g, a, ls, ps, g->sel);
    compose(frame, g, list);
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
    pseudo_t ps;
    memset(&ps, 0, sizeof(ps));
    if (ready && have_draw && have_frame) {
        funcs_fill(&list, &arena, &g.an);
        while (turn(&g, &arena, &frame, &list, &ls, &ps))
            ;
    }
    re_term_close(&g.term);
    if (ready)
        re_analysis_close(&g.an);
    re_arena_free(&arena);
    return ready ? 0 : 2;
}
