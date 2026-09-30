// re_tui.c - the environment policy and the flat parts of a report.
// Module: util (C11).
// Owns: the output policy, the width, the colour styles, and the flat report elements.
// Depends: re_tui.h. Reads the environment and asks the OS whether stdout is a terminal.
#include "utils/re_tui.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#    include <io.h>
#    define RE_ISATTY(fd) _isatty(fd)
#    define RE_FILENO(f) _fileno(f)
#else
#    include <unistd.h>
#    define RE_ISATTY(fd) isatty(fd)
#    define RE_FILENO(f) fileno(f)
#endif

// The style escapes, one table so no caller writes one. Each style resets to default
// at the end, which is what keeps a styled fragment from colouring whatever comes
// after it if the output is concatenated somewhere unexpected.
typedef struct {
    const char *on;
    const char *off;
} style_t;

static const style_t kStyles[RE_ST_BAD + 1] = {
    {"", ""},                  // none
    {"\x1b[1;7m", "\x1b[0m"},  // title, inverted
    {"\x1b[1m", "\x1b[0m"},    // head, bold
    {"\x1b[2m", "\x1b[0m"},    // label, dim
    {"\x1b[1;36m", "\x1b[0m"}, // accent, bold cyan
    {"\x1b[32m", "\x1b[0m"},   // good, green
    {"\x1b[33m", "\x1b[0m"},   // warn, yellow
    {"\x1b[1;31m", "\x1b[0m"}, // bad, bold red
};

bool re_tui_is_tty(void) {
    return RE_ISATTY(RE_FILENO(stdout)) != 0;
}

uint16_t re_tui_term_width(void) {
    const char *cols = getenv("COLUMNS");
    if (cols && *cols) {
        long v = strtol(cols, NULL, 10);
        if (v >= (long)RE_TUI_MIN_WIDTH)
            return v > 200 ? (uint16_t)200 : (uint16_t)v;
    }
    return RE_TUI_DEFAULT_WIDTH;
}

bool re_tui_want_color(void) {
    // NO_COLOR is a near universal expectation, so it is honoured here rather than
    // left to every caller. The variable being present at all is what counts, even
    // when empty, which is what the convention specifies.
    const char *nc = getenv("NO_COLOR");
    return !(nc != NULL);
}

bool re_tui_want_unicode(void) {
    // Windows Terminal and every POSIX terminal render UTF-8, so the default is yes.
    // The ascii path is for a pipe that a person still has to read, where the box
    // characters would otherwise be mojibake in a log.
    const char *legacy = getenv("RE_TUI_ASCII");
    return !(legacy != NULL);
}

void re_tui_init(re_tui_t *t, re_strbuf_t *out, re_strbuf_t *scratch, bool color, bool unicode,
                 uint16_t width) {
    t->out = out;
    t->scratch = scratch;
    t->width = width < RE_TUI_MIN_WIDTH ? RE_TUI_DEFAULT_WIDTH : width;
    t->color = color;
    t->unicode = unicode;
}

void re_tui_styled(re_strbuf_t *dst, const re_tui_t *t, re_style_t style, const char *s) {
    if (!t->color || style == RE_ST_NONE) {
        re_strbuf_puts(dst, s ? s : "");
        return;
    }
    re_strbuf_puts(dst, kStyles[style].on);
    re_strbuf_puts(dst, s ? s : "");
    re_strbuf_puts(dst, kStyles[style].off);
}

void re_tui_fill(re_strbuf_t *dst, const re_tui_t *t, size_t n, const char *with) {
    (void)t;
    for (size_t i = 0; i < n; i++)
        re_strbuf_puts(dst, with);
}

void re_tui_rule(re_tui_t *t) {
    re_tui_fill(t->out, t, t->width, t->unicode ? "\xe2\x94\x80" : "-");
    re_strbuf_putc(t->out, '\n');
}

void re_tui_header(re_tui_t *t, const char *left, const char *right) {
    // The bar is one styled run rather than styled in pieces, so the inverse attribute
    // covers the padding and not just the text. A half inverted bar is the single most
    // visible way for this to look wrong. The scratch buffer belongs to the caller
    // because this utility keeps no state, and because a header is not reentrant with
    // one scratch buffer anyway.
    re_strbuf_t *scratch = t->scratch;
    size_t lw = re_tui_cols(left);
    size_t rw = re_tui_cols(right);
    size_t pad = t->width > lw + rw ? t->width - lw - rw : 1;
    re_strbuf_clear(scratch);
    re_strbuf_puts(scratch, left ? left : "");
    for (size_t i = 0; i < pad; i++)
        re_strbuf_putc(scratch, ' ');
    re_strbuf_puts(scratch, right ? right : "");
    re_tui_styled(t->out, t, RE_ST_TITLE, scratch->p ? scratch->p : "");
    re_strbuf_putc(t->out, '\n');
}

void re_tui_tabs(re_tui_t *t, const char *const *labels, size_t n, size_t active) {
    if (n > RE_TUI_MAX_PANELS * 2)
        n = RE_TUI_MAX_PANELS * 2;
    for (size_t i = 0; i < n; i++) {
        if (i)
            re_tui_styled(t->out, t, RE_ST_LABEL, " | ");
        re_tui_styled(t->out, t, i == active ? RE_ST_ACCENT : RE_ST_LABEL,
                      labels[i] ? labels[i] : "");
    }
    re_strbuf_putc(t->out, '\n');
}
