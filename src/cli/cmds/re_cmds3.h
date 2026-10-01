// re_cmds3.h - entry points for the disassembly commands.
// Module: cli (C11).
// Owns: nothing. Declares the funcs, xrefs, jtables, disasm and decompile entry points.
// Depends: cli/re_table.h for re_ctx_t. Every command returns a process exit code.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "cli/app/re_table.h"

int re_cmd_funcs(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_xrefs(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_jtables(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_disasm(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_decompile(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_regions(re_ctx_t *ctx, const char *path, int argc, char **argv);
int re_cmd_cfg(re_ctx_t *ctx, const char *path, int argc, char **argv);
#ifdef __cplusplus
}
#endif
