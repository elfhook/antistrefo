// re_layout.h - the description of the reference screen arrangement, as data.
// Module: util (C11).
// Owns: the re_layout_t struct and the one function that composes it onto a screen.
// Depends: re_screen.h, re_strbuf. Holds no state between calls.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/tui/re_screen.h"

// Everything the arrangement draws, as plain fields. A struct of pointers rather than
// a builder API, because the arrangement is filled in once per redraw by the caller
// and a builder would only add a second spelling of the same thing.
//
// The order of the fields is the order of the bands on screen, top to bottom, so a
// reader of the header can see the layout without opening the layout.
typedef struct {
    // the subject, centred on the top row
    const char *file;

    // the row of controls
    const char *const *toolbar;
    size_t n_toolbar;

    // position within the whole, with a handle on a track
    size_t nav_pos;
    size_t nav_total;

    // what the shapes in the body mean
    const char *const *legend;
    size_t n_legend;

    // the left pane: a framed list with a heading and one selected row
    const char *list_title;
    const char *list_head;
    const char *const *rows;
    size_t n_rows;
    size_t sel_row;

    // the right pane: a tab strip over a numbered code view
    const char *const *tabs;
    size_t n_tabs;
    size_t active_tab;
    const char *const *code;
    size_t n_code;
    uint32_t base_line;
    const uint8_t *marks; // one byte per code line: nonzero where there is a mark
    size_t scroll_pos;
    size_t scroll_total;

    // the bottom row: the subject on the left, the caret on the right
    const char *status;
    const char *caret;

    // the split. 0 asks for the minimum, which is the honest answer on a narrow
    // terminal rather than a pane one column wide.
    uint16_t left_w;
} re_layout_t;

// Draw the arrangement onto a screen. Clips to the screen, refuses rather than
// truncates when the screen is too short to hold it, and returns how many rows the
// body ended up with so a caller that scrolls can tell whether anything was cut.
uint16_t re_layout_compose(re_screen_t *s, const re_layout_t *L);
#ifdef __cplusplus
}
#endif
