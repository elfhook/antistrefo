// re_gui.h - the full screen front end: a session over a whole file.
// Module: cli (C11).
// Owns: the interactive state and the loop, and nothing about how it is drawn.
// Depends: re_term, re_input, re_focus, re_draw, re_screen, re_layout, re_analysis.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

// Open a file in the full screen view and run until the reader leaves. Returns a
// process exit code like every other command, so this is the same tool rather than a
// second one.
//
// Fails, without taking the terminal, when either end is not a terminal. A view that
// needs a screen cannot be printed to a pipe, and pretending otherwise produces escape
// sequences in someone's log.
int re_cmd_gui(re_ctx_t *ctx, const char *path, int argc, char **argv);

#ifdef __cplusplus
}
#endif
