// re_report.h - the scaffold every text renderer builds its report on.
// Module: cli (C11).
// Owns: starting a report, and the decision of whether one is wanted at all.
// Depends: re_tui, re_ctx, re_arena. A renderer fills panels and calls re_report_end.
//
// A renderer is a function that re-derives the same facts the JSON path does and lays
// them out. That is duplication on purpose: the JSON shape is a contract with the MCP
// server and with anything parsing this tool, and it must not be reshaped to suit a
// screen. The two agree because both read the same feature APIs, not because one is
// generated from the other.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_tui.h"
#include "cli/app/re_table.h"

// A report in progress: the buffer it is written into, the tui state, and the panels
// the current section is filling.
typedef struct {
    re_strbuf_t buf;
    re_strbuf_t scratch;
    re_tui_t tui;
    const char *const *sections; // remembered so head can be a separate call
    size_t n_sections;
    const re_ctx_t *ctx; // remembered so a report can be reopened mid session
} re_report_t;

// True when the caller should render a framed report rather than JSON. This is the
// whole output policy in one place, so a renderer never has to think about it and
// there is exactly one answer to "when is it text".
bool re_report_wanted(const re_ctx_t *ctx);

// Open a report: the buffers and the tui state. The header comes separately because a
// renderer has to build its subject line first, and the subject needs the loaded file.
void re_report_open(re_report_t *r, re_arena_t *a, const re_ctx_t *ctx, const char *const *sections,
                    size_t n_sections);

// The header bar and the tab row. The bar names the subject on the left and a one
// line summary on the right; the tab row names the sections, so it doubles as a
// contents line. Opening and heading are separate so the subject can be built from
// the file that open did not need to parse.
void re_report_head(re_report_t *r, const char *subject, const char *summary);

// Flush to stdout. Every renderer ends here, so the flush and the newline handling
// live in one place.
void re_report_end(re_report_t *r);

// A heading inside a panel, styled so a reader can find the group.
void re_panel_head(re_tui_t *t, re_panel_t *p, const char *s);

// Format a short value into the report's own scratch buffer, for a key or a value that
// is needed as text. The result is valid until the next call, which is all a key/value
// line needs, and it is built from the report's arena.
//
// This exists because the obvious thing to write is a local strbuf initialised with a
// null arena, and appending to one dereferences the null arena. A renderer needs this
// function rather than a raw buffer, and that is the point of it.
const char *re_report_tmp(re_report_t *r, const char *fmt, ...);

// One styled line into the report buffer, for a message between reports.
void re_report_note(re_report_t *r, re_style_t style, const char *msg);

// Write a prompt and flush, without a newline. This is the shell's only reason to
// write outside a report, and it goes through here so there is still one place that
// writes to stdout rather than a second one inside the loop.
void re_report_prompt(re_report_t *r, const char *text);

// Write a bare newline, to end the line a report left the cursor on.
void re_report_newline(re_report_t *r);

// A full width panel holding a table, which is the shape every list shaped command
// wants. Wrapping the tui table rather than repeating it keeps a renderer down to the
// facts it is reporting, which is the only part that should differ between commands.
typedef struct {
    re_panel_t p;
    re_tui_table_t tt;
    re_report_t *r;
} re_table_t;

// widths may be NULL, in which case every column is measured from its own content and
// the last one takes the rest of the width.
void re_table_begin(re_table_t *t, re_report_t *r, const char *title, const size_t *widths,
                    size_t ncols);
void re_table_head(re_table_t *t, const char *const *cols);
void re_table_row(re_table_t *t, const char *const *cells);
void re_table_end(re_table_t *t);

// Print a size in the form a person reads: bytes, or KiB and up once it is large
// enough that a raw count stops being useful. The exact byte count is in the JSON.
void re_fmt_size_human(re_strbuf_t *out, uint64_t bytes);

#ifdef __cplusplus
}
#endif
