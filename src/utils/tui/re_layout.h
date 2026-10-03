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
    // the subject. Drawn on the menu row, left of the version, and clipped to the gap.
    const char *file;

    // the right end of the menu row, in angle brackets. The product version lives here.
    const char *mark;

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

    // the right pane: page names on the body's top edge, content under them
    const char *const *tabs;
    size_t n_tabs;
    size_t active_tab;
    const char *const *code;
    size_t n_code;
    uint32_t base_line;
    const uint8_t *marks; // one byte per code line: nonzero where there is a mark
    bool syntax;          // colour the code pane as C-like source
    size_t scroll_pos;
    size_t scroll_total;

    // the bottom row: the subject on the left, the caret on the right
    const char *status;
    const char *caret;

    // the split. 0 asks for the minimum, which is the honest answer on a narrow
    // terminal rather than a pane one column wide.
    uint16_t left_w;

    // The first screen, before there is a file. When welcome is set the body is one
    // framed box carrying the message and a single button, and the split, the list and
    // the code pane are all left out rather than drawn empty. An empty pane reads as a
    // file with nothing in it, which is a different and wrong claim.
    const char *welcome;
    const char *button;

    // Which control the button is, so a caller can tell a click on it from a click
    // anywhere else. Set by re_layout_compose, because the id is handed out in drawing
    // order and only the composer knows what order it drew in.
    uint8_t button_zone;

    // The first toolbar control. The view's first item is File, and that is the load
    // control once the welcome box is gone. Same rule as button_zone: the composer
    // fills it in, because the id depends on what was drawn before it.
    uint8_t open_zone;

    // The first page tab, and how many were actually drawn. A narrow row stops early,
    // and a click past that would land on a function row if the count were a guess.
    uint8_t tab_zone;
    uint8_t tabs_drawn;

    // The first function row, and how many were drawn. A click on a name selects that
    // function, and the count is what keeps the binding off a zone that is not a row.
    uint8_t row_zone;
    uint8_t rows_drawn;
} re_layout_t;

// Draw the arrangement onto a screen. L is not const because the composer fills in
// button_zone, and only it knows the id: zones are handed out in drawing order. Clips to the
// screen, refuses rather than truncates when the screen is too short to hold it, and returns how
// many rows the body ended up with so a caller that scrolls can tell whether anything was cut.
uint16_t re_layout_compose(re_screen_t *s, re_layout_t *L);
#ifdef __cplusplus
}
#endif
