// re_render.h - the text renderers, one per command.
// Module: cli (C11).
// Owns: the framed report each command prints when a person is reading it.
// Depends: re_prep, re_report, re_tui. Reads the same feature APIs the JSON path
//           reads; never writes a second source of truth.
//
// Each command calls its renderer and returns, or falls through to JSON. Which one is
// the re_report_wanted decision, and it is made in exactly one place.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

// Every renderer returns a process exit code, like a command, so a caller can return
// its result directly. Each loads the file itself: the commands already do, and
// sharing the loaded record across both would mean holding a mapped file open for the
// sake of a format that is usually not the one being used.
int re_render_info(re_ctx_t *ctx, const char *path);
int re_render_sections(re_ctx_t *ctx, const char *path);
int re_render_imports(re_ctx_t *ctx, const char *path);
int re_render_exports(re_ctx_t *ctx, const char *path);
int re_render_funcs(re_ctx_t *ctx, const char *path);
#ifdef __cplusplus
}
#endif
