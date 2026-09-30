// re_cmds3.h - entry points for the disassembly commands.
// Module: cli (C11).
// Owns: nothing. Declares the funcs, disasm and xrefs entry points.
// Depends: cli/re_table.h for re_ctx_t. Every command returns a process exit code.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/re_table.h"

int re_cmd_funcs(re_ctx_t *ctx, const char *path, int argc, char **argv);
#ifdef __cplusplus
}
#endif
