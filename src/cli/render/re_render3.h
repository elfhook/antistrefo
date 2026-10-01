// re_render3.h - the framed report for the analyze command.
// Module: cli (C11).
// Owns: the text rendering of analyze.
// Depends: re_table.h for re_ctx_t.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

int re_render_analyze(re_ctx_t *ctx, const char *path);
#ifdef __cplusplus
}
#endif
