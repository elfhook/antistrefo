// re_table.h - the one command table that feeds both the CLI and the MCP tool list.
// Module: cli (C11).
// Owns: command metadata, shared argument parsing and the dispatch contract.
// Depends: re_str, re_strbuf, re_err. No globals except the table itself.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/re_arena.h"
#include "utils/re_err.h"
#include "utils/re_str.h"
#include "utils/re_strbuf.h"

#define RE_CMD_NAME_MAX 24
#define RE_CMD_SUMMARY_MAX 96
#define RE_CMD_MAX_ARGS 16

typedef enum {
    RE_FMT_OUT_JSON = 0,
    RE_FMT_OUT_TEXT,
} re_out_fmt_t;

typedef struct re_ctx {
    re_arena_t *arena;
    re_out_fmt_t out;
    size_t limit; // default 200, the agent context guard
    size_t offset;
    uint64_t off;   // hexdump offset
    uint64_t len;   // hexdump length
    re_str_t regex; // empty when no filter was given
    bool has_regex;
    re_err_t *err;
} re_ctx_t;

// Every command receives the already parsed context, so no command re-parses argv
// and the MCP layer can synthesise the same context from a tool call.
typedef int (*re_cmd_fn)(re_ctx_t *ctx, const char *path, int argc, char **argv);

typedef struct {
    char name[RE_CMD_NAME_MAX];
    char summary[RE_CMD_SUMMARY_MAX];
    char usage[64];
    re_cmd_fn fn;
    bool needs_path;
} re_cmd_t;

const re_cmd_t *re_cmd_table(size_t *count);
const re_cmd_t *re_cmd_find(const char *name);

// Parse the flags every command shares. Returns false and fills err on a bad flag,
// so a command only ever sees the positional path.
bool re_cmd_parse(re_ctx_t *ctx, int argc, char **argv, int *first_positional, re_err_t *err);

// Write the envelope every response carries, so no command can forget it.
void re_cmd_begin(re_ctx_t *ctx, re_strbuf_t *head);
#ifdef __cplusplus
}
#endif
