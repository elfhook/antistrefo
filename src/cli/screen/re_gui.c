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
#include "utils/mem/re_buf.h"
#include "utils/tui/re_layout.h"
#include "utils/tui/re_screen.h"
#include "cli/screen/re_draw.h"
#include "cli/screen/re_focus.h"
#include "cli/screen/re_gui_model.h"
#include "cli/screen/re_input.h"
#include "cli/screen/re_pseudocode.h"
#include "cli/screen/re_term.h"

#include <stdio.h>
#include <string.h>

// How much a listing holds at once. Bounded rather than sized to the file, because a
// pane has a fixed number of rows and a function can be longer than any of them.
#define LIST_ROWS RE_GUI_LIST_ROWS

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
    bool want_load;  // the load control was activated
    bool loaded;     // a file is open, so the body is the file view
    bool fana_ready; // the analysis arena holds a mapping
    uint8_t button_zone;
    // The analysis gets its own arena, freed and remade on every load, because a mapped
    // binary is arena memory and a session that opened twenty of them would run out.
    // The path is copied rather than borrowed for the same reason: the analysis arena
    // goes away on a reload, and the title still has to name what is loaded.
    re_arena_t fana;
    char path[512];
    // What the right pane shows, decided once per turn by the active tab and filled in
    // by whichever pass produced it. Keeping it here rather than in compose is what
    // lets the layout stay ignorant of where its text came from.
    const char **body;
    const uint8_t *body_marks;
    size_t body_n;
    uint32_t body_base;
    const char *body_note;
} gui_t;

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

// Split the emitted body into lines. The buffer is left intact apart from the line
// endings, which become terminators, so the pointers are C strings and the grid never
// sees a newline inside a cell.
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
// which is why the two take different paths.
static void body_for(gui_t *g, re_arena_t *a, re_gui_listing_t *ls, pseudo_t *ps, size_t sel) {
    if (g->tab == 1) {
        pseudo_fill(ps, a, &g->an, sel);
        g->body = ps->line;
        g->body_marks = ps->mark;
        g->body_n = ps->n;
        g->body_base = 0;
        return;
    }
    re_gui_listing_fill(ls, a, &g->an, sel);
    g->body = ls->text;
    g->body_marks = ls->mark;
    g->body_n = ls->n;
    g->body_base = ls->base;
}

static void compose(re_screen_t *s, gui_t *g, const re_gui_funcs_t *l) {
    static const char *kTabs[RE_TAB_COUNT] = {"Disasm", "Pseudocode"};
    static const char *kToolbar[] = {"Open", "Save", "Graph", "Strngs", "Xrefs", "Help"};
    static const char *kLegend[] = {"code", "branch", "gap", "selected"};

    re_layout_t L = {0};
    L.toolbar = kToolbar;
    L.n_toolbar = 6;
    L.legend = kLegend;
    L.n_legend = 4;
    L.left_w = 30;
    g->button_zone = RE_SCREEN_ZONE_NONE;

    if (!g->loaded) {
        // The first screen. No list, no panes, no empty function table: a pane drawn
        // with nothing in it reads as a file that has no functions, which is a
        // different and wrong claim.
        L.file = "antistrefo";
        L.welcome = "load a file here";
        L.button = "Load";
        L.status = "no file";
        L.caret =
            g->mouse ? "click Load, or drop a file on this window" : "press Enter to load a file";
        re_layout_compose(s, &L);
        g->button_zone = L.button_zone;
        re_focus_build(&g->focus, s);
        return;
    }

    const char *lrows[LIST_ROWS];
    re_gui_funcs_window(g->sel, l, lrows, LIST_ROWS);

    char status[80];
    snprintf(status, sizeof(status), "%u functions", (unsigned)l->n);

    L.file = g->path;
    L.nav_pos = g->sel;
    L.nav_total = l->n;
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
    re_layout_compose(s, &L);
    re_focus_build(&g->focus, s);
}
// Open a file into the session, replacing whatever was there. The analysis arena is
// remade rather than grown into: a mapped binary is arena memory, and a session that
// loaded twenty of them would exhaust one arena instead of saying so.
static bool load_file(gui_t *g, re_arena_t *a, re_gui_funcs_t *list, pseudo_t *ps,
                      const char *path) {
    if (g->fana_ready) {
        re_analysis_close(&g->an);
        g->fana_ready = false;
    }
    re_arena_free(&g->fana);
    re_arena_init(&g->fana, 1u << 23);
    if (!re_analysis_open(&g->an, &g->fana, path)) {
        // Keep whatever was open. Failing a load must not cost the reader the file they
        // were already reading, which is the one thing they cannot get back.
        return false;
    }
    g->fana_ready = true;
    size_t n = 0;
    while (path[n] && n + 1u < sizeof(g->path)) {
        g->path[n] = path[n];
        n++;
    }
    g->path[n] = '\0';
    g->loaded = true;
    g->sel = 0;
    g->tab = 0;
    // The caches are keyed on the function index, and the function list is a different
    // list now, so both have to be told the old answers no longer apply.
    ps->built_for = (size_t)-1;
    list->n = 0;
    re_gui_funcs_fill(list, a, &g->an);
    return true;
}

// The prompt. It steps out of the full screen and back to cooked input, because a
// question asked with the cursor hidden and echo off is a question asked badly. This
// is the same affordance the shell's "open" gives, deliberately: one way to name a file
// in this tool, not two that drift apart.
static bool prompt_path(gui_t *g, char *out, size_t cap) {
    static const char kAsk[] = "\n  load a file (empty to go back): ";
    static const char kDone[] = "\n";
    re_term_pause(&g->term);
    // Written through the terminal layer rather than to stdout directly, so the one
    // path bytes take to a terminal is the one the rest of the front end uses.
    re_term_write(&g->term, kAsk, sizeof(kAsk) - 1u);
    char line[512];
    bool got = fgets(line, (int)cap, stdin) != NULL;
    re_term_write(&g->term, kDone, sizeof(kDone) - 1u);
    re_term_resume(&g->term);
    if (!got)
        return false;
    size_t n = 0;
    while (line[n] && line[n] != '\n' && line[n] != '\r')
        n++;
    line[n] = '\0';
    // Trim the surrounding spaces a pasted path usually carries. A path that legitimately
    // ends in one is not a thing anybody means to type.
    while (n && (line[0] == ' ')) {
        for (size_t i = 0; i + 1 < n; i++)
            line[i] = line[i + 1];
        n--;
        line[n] = '\0';
    }
    for (size_t i = 0; i < n; i++)
        out[i] = line[i];
    out[n] = '\0';
    return n > 0;
}

static void apply(gui_t *g, const re_ev_t *ev) {
    if (ev->kind == RE_EV_KEY) {
        switch (ev->key) {
            case 'q':
            case 'Q':
            case RE_KEY_ESCAPE:
                // Before a file is open, leaving is still what Escape should do. The
                // button is reached with Enter and Tab, so nothing is lost.
                g->quit = true;
                return;
            case RE_KEY_ENTER:
            case 'l':
            case 'L':
                if (!g->loaded)
                    g->want_load = true;
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
static bool turn(gui_t *g, re_arena_t *a, re_screen_t *frame, re_gui_funcs_t *list,
                 re_gui_listing_t *ls, pseudo_t *ps) {
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

bool re_gui_wants_file(const char *arg) {
    if (!arg || !*arg)
        return false;
    // Something readable is there, not something with a known extension. A dropped
    // binary may be named anything, and refusing one over its extension would be
    // refusing the only thing the reader asked for.
    //
    // The file is read and thrown away, so opening it again costs one more read. That
    // is cheaper than a wrong answer: without a check, a mistyped command would open
    // this instead of saying the command does not exist.
    re_arena_t a;
    re_arena_init(&a, 0);
    re_file_t f;
    bool ok = re_file_open(arg, &a, &f) == RE_OK;
    re_arena_free(&a);
    return ok;
}

int re_cmd_gui(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    (void)ctx;
    // No file is not an error. Opening the binary with nothing named is the case the
    // welcome screen exists for, so the path is optional and its absence is the state.
    gui_t g;
    memset(&g, 0, sizeof(g));
    re_arena_t arena;
    re_arena_init(&arena, 1u << 23);
    re_gui_funcs_t list;
    memset(&list, 0, sizeof(list));
    re_gui_listing_t ls;
    memset(&ls, 0, sizeof(ls));
    pseudo_t ps;
    memset(&ps, 0, sizeof(ps));

    // The terminal is taken before the file is analysed. The other order puts a full
    // screen session up and then prints a failure into it, which leaves the reader with
    // escape sequences and no way back.
    if (!re_term_open(&g.term, true)) {
        fprintf(stderr, "gui needs a terminal on both ends; try the report commands\n");
        re_arena_free(&arena);
        return 2;
    }
    g.mouse = re_term_has_mouse(&g.term);

    // A named file is loaded now. Without one the first screen is the welcome, which is
    // what opening the binary by double clicking it should produce, so this is not a
    // different code path: it is the same one with nothing to load yet.
    bool ready = !*path || load_file(&g, &arena, &list, &ps, path);
    uint16_t rows = 24, cols = 80;
    re_term_size(&rows, &cols);
    bool have_draw = re_draw_init(&g.draw, &arena, rows, cols);
    re_screen_t frame;
    bool have_frame = re_screen_init(&frame, &arena, &g.draw.out, rows, cols);
    re_focus_init(&g.focus);
    if (have_draw && have_frame) {
        while (turn(&g, &arena, &frame, &list, &ls, &ps)) {
            if (g.want_load) {
                char typed[512];
                g.want_load = false;
                if (prompt_path(&g, typed, sizeof(typed)))
                    load_file(&g, &arena, &list, &ps, typed);
            }
        }
    }
    re_term_close(&g.term);
    if (g.fana_ready)
        re_analysis_close(&g.an);
    re_arena_free(&arena);
    return ready ? 0 : 2;
}
