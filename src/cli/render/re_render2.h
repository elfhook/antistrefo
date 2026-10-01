// re_render2.h - the text renderers for the analysis commands.
// Module: cli (C11).
// Owns: the framed reports cfg and regions print when a person is reading them.
// Depends: re_table.h for re_ctx_t. Like the other renderers, each loads the file
//           itself rather than sharing a loaded record with the JSON path.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

// cfg takes the address separately because a renderer is reached without argv, and a
// control flow graph is about one function, so which one is part of the request
// rather than an option. addr may be NULL, which means the first function found.
int re_render_cfg(re_ctx_t *ctx, const char *path, const char *addr);
int re_render_regions(re_ctx_t *ctx, const char *path);
#ifdef __cplusplus
}
#endif
