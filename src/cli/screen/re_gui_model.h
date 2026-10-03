// re_gui_model.h - what the front end shows about a file, without knowing how.
// Module: cli (C11).
// Owns: the function list, the instruction listing, and their buffers.
// Depends: re_analyze, re_code, re_strbuf, re_arena. Builds no screen and reads no
//           terminal, so the fill functions can be reasoned about on their own.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/analysis/re_analyze.h"
#include "utils/mem/re_arena.h"

// A pane's worth, not a promise about the file: a function can be longer than any pane
// and a terminal has a fixed number of rows.
#define RE_GUI_CODE_MAX 48u
#define RE_GUI_LIST_MAX 256u
#define RE_GUI_LIST_ROWS 24u

typedef struct {
    re_strbuf_t line[RE_GUI_CODE_MAX];
    const char *text[RE_GUI_CODE_MAX];
    uint8_t mark[RE_GUI_CODE_MAX];
    size_t n;
    uint32_t base;
    size_t vis;
} re_gui_listing_t;

typedef struct {
    char *name[RE_GUI_LIST_MAX];
    char addr[RE_GUI_LIST_MAX][20];
    size_t n;
    size_t vis;
} re_gui_funcs_t;

// The functions of the open file, with a name for each: an unnamed one gets one
// derived from its address, so the list never shows a blank row indistinguishable from
// any other blank row.
void re_gui_funcs_fill(re_gui_funcs_t *l, re_arena_t *a, const re_analysis_t *an);

// The rows the list shows, kept centred on sel so the reader always sees what they
// moved to.
void re_gui_funcs_window(size_t sel, const re_gui_funcs_t *l, const char **rows, size_t cap);

// The disassembly of one function, decoded and rendered through the shared backend, so
// the listing and a report cannot disagree about an address.
void re_gui_listing_fill(re_gui_listing_t *ls, re_arena_t *a, const re_analysis_t *an, size_t sel);

#ifdef __cplusplus
}
#endif
