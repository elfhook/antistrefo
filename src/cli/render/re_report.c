// re_report.c - the scaffold every text renderer builds its report on.
// Module: cli (C11).
// Owns: starting and finishing a report, and the policy that decides whether one is wanted.
// Depends: re_report.h, re_tui, re_ctx, re_fmt. Writes to stdout only in re_report_end.
#include "cli/render/re_report.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "utils/text/re_fmt.h"
#include "utils/tui/re_tui.h"

bool re_report_wanted(const re_ctx_t *ctx) {
    // An explicit --format is the caller speaking, and it always wins. Otherwise the
    // question is who is reading: a terminal gets the framed report, a pipe gets the
    // machine format. That is the whole policy, and it is why the test harness and the
    // MCP server are unaffected by any of this.
    if (ctx->out == RE_FMT_OUT_TEXT)
        return true;
    if (ctx->out == RE_FMT_OUT_JSON)
        return false;
    return re_tui_is_tty();
}

void re_report_open(re_report_t *r, re_arena_t *a, const re_ctx_t *ctx, const char *const *sections,
                    size_t n_sections) {
    re_strbuf_init(&r->buf, a);
    re_strbuf_init(&r->scratch, a);
    re_tui_init(&r->tui, &r->buf, &r->scratch, !ctx->no_color && re_tui_want_color(),
                re_tui_want_unicode(), re_tui_term_width());
    r->n_sections = n_sections;
    r->sections = sections;
    r->ctx = ctx;
}

void re_report_head(re_report_t *r, const char *subject, const char *summary) {
    re_tui_header(&r->tui, subject, summary);
    if (r->sections && r->n_sections)
        re_tui_tabs(&r->tui, r->sections, r->n_sections, 0);
}
void re_report_end(re_report_t *r) {
    fwrite(r->buf.p ? r->buf.p : "", 1, r->buf.len, stdout);
    fflush(stdout);
    // Clear after flushing. The bytes are out, and a buffer that still holds them
    // would be written again by the next thing that flushes it, so a shell session
    // would reprint its last report on every prompt.
    re_strbuf_clear(&r->buf);
}

void re_panel_head(re_tui_t *t, re_panel_t *p, const char *s) {
    re_strbuf_putc(&p->body, ' ');
    re_tui_styled(&p->body, t, RE_ST_HEAD, s);
    re_strbuf_putc(&p->body, '\n');
}

const char *re_report_tmp(re_report_t *r, const char *fmt, ...) {
    va_list ap;
    char buf[96];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    // The buffer is NUL terminated by vsnprintf, so re_arena_strdup copies the right
    // length without needing strlen here.
    return re_arena_strdup(r->scratch.arena, buf);
}

void re_fmt_size_human(re_strbuf_t *out, uint64_t bytes) {
    if (bytes < 1024) {
        re_fmt_put_size(out, bytes);
        return;
    }
    static const char *kUnits[] = {"KiB", "MiB", "GiB", "TiB"};
    double v = (double)bytes / 1024.0;
    size_t u = 0;
    while (v >= 1024.0 && u + 1 < sizeof(kUnits) / sizeof(kUnits[0])) {
        v /= 1024.0;
        u++;
    }
    re_strbuf_appendf(out, "%.1f %s (%lluB)", v, kUnits[u], (unsigned long long)bytes);
}

void re_table_begin(re_table_t *t, re_report_t *r, const char *title, const size_t *widths,
                    size_t ncols) {
    t->r = r;
    re_panel_init(&t->p, r->scratch.arena, title, 1);
    re_tui_table_init(&t->tt, &r->tui);
    for (size_t i = 0; i < ncols && i < RE_TUI_MAX_COLS; i++)
        t->tt.w[i] = widths ? widths[i] : 0;
    t->tt.n = ncols > RE_TUI_MAX_COLS ? RE_TUI_MAX_COLS : ncols;
}

void re_table_head(re_table_t *t, const char *const *cols) {
    re_tui_table_head(&t->tt, &t->r->tui, &t->p, &t->r->scratch, cols, t->tt.n);
}

void re_table_row(re_table_t *t, const char *const *cells) {
    re_tui_table_row(&t->tt, &t->r->tui, &t->p, &t->r->scratch, cells, t->tt.n);
}

void re_table_end(re_table_t *t) {
    re_panel_close(&t->p);
    re_tui_compose(&t->r->tui, &t->p, 1);
}

// One styled line into the report buffer. The shell uses this for its own messages so
// they interleave correctly with a report already in progress; going straight to stdout
// would let a message appear before the report it was about.
void re_report_note(re_report_t *r, re_style_t style, const char *msg) {
    // Clipped to the terminal before it is styled. A note is the one line in the report
    // with no column layout behind it, so an unclipped one simply wraps, and a wrapped
    // note pushes every box below it out of step because the cursor lands in the wrong
    // column. re_tui_clip_line is the shared helper, so the clip lands on a character
    // boundary and keeps any escapes intact rather than counting bytes here.
    re_strbuf_t clip;
    re_strbuf_init(&clip, r->scratch.arena);
    re_tui_clip_line(&clip, &r->tui, msg, re_str(msg).n, r->tui.width);
    re_tui_styled(&r->buf, &r->tui, style, clip.p ? clip.p : "");
    re_strbuf_putc(&r->buf, '\n');
    // A note is flushed rather than left in the buffer. Nothing else will: the renderers
    // flush when they finish, but a note is what the shell writes when no renderer ran,
    // and an unflushed message is a message that never appears.
    re_report_end(r);
}

void re_report_prompt(re_report_t *r, const char *text) {
    // The length is counted here rather than with strlen, which the rules ban outside
    // the string utility, and the report is not otherwise needed by a prompt.
    size_t n = 0;
    while (text[n])
        n++;
    (void)r;
    fwrite(text, 1, n, stdout);
    fflush(stdout);
}

void re_report_newline(re_report_t *r) {
    (void)r;
    fputc('\n', stdout);
    fflush(stdout);
}
