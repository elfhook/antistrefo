// main.cpp - entry point, dispatch and the error envelope. Thin by design.
// Module: cli (C++17).
// Owns: startup ordering, table driven dispatch, exit codes, error reporting.
// Depends: re_table, re_cmds, re_mcp, the utils. stdout only via the emitters.
#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#    include <fcntl.h>
#    include <io.h>
#endif

#include "utils/re_util.h"
#include "cli/re_cmds.h"
#include "cli/re_shell.h"
#include "cli/re_table.h"
#include "mcp/re_mcp.h"

namespace {

constexpr const char *kName = "antistrefo";
constexpr const char *kVersion = "0.1.0";
constexpr const char *kSchema = "antistrefo/1";
constexpr const char *kDesc =
    "AI driven static analyzer for reverse engineering applications, libraries, or whatever you "
    "want";

void print_usage() {
    std::fprintf(stderr, "%s %s - %s\n\nusage:\n", kName, kVersion, kDesc);
    size_t count = 0;
    const re_cmd_t *table = re_cmd_table(&count);
    for (size_t i = 0; i < count; i++) {
        if (!table[i].fn && !re_str_eq_cstr(re_str(table[i].name), "help") &&
            !re_str_eq_cstr(re_str(table[i].name), "version") &&
            !re_str_eq_cstr(re_str(table[i].name), "mcp"))
            continue;
        std::fprintf(stderr, "  %-10s %s\n", table[i].usage, table[i].summary);
    }
    std::fprintf(stderr, "\n  global flags: --format json|text  --limit N  --offset N\n");
    std::fprintf(stderr, "  every response carries schema \"%s\"\n", kSchema);
}

// Errors go to stderr as a JSON object, never to stdout, so a partially written
// response on stdout is never mistaken for an error by the caller.
int report_error(const re_err_t &err) {
    re_arena_t arena;
    re_arena_init(&arena, 4096);
    re_jw_t w;
    re_jw_init(&w, &arena);
    re_jw_obj(&w);
    re_jw_kcstr(&w, "schema", kSchema);
    re_jw_key(&w, "error");
    re_jw_obj(&w);
    re_jw_kcstr(&w, "code", re_err_str(err.code));
    re_jw_kstr(&w, "message", re_strn(re_err_msg(&err), re_str(re_err_msg(&err)).n));
    re_jw_ku64(&w, "exit", (uint64_t)re_err_exit_code(err.code));
    re_jw_obj_end(&w);
    re_jw_obj_end(&w);
    re_jw_flush(&w, stderr);
    re_arena_free(&arena);
    return re_err_exit_code(err.code);
}

// Run the interactive shell. Its arena outlives the whole session, unlike the
// per command arena below, because the remembered file has to survive between lines.
int run_shell() {
    re_arena_t arena;
    re_err_t err{};
    re_ctx_t ctx{};
    re_arena_init(&arena, 256u * 1024u);
    err.code = RE_OK;
    ctx.arena = &arena;
    ctx.err = &err;
    int rc = re_shell_run(&ctx);
    re_arena_free(&arena);
    return rc;
}

} // namespace

int main(int argc, char **argv) {
    re_log_init_from_env();
    re_crc_init();
#if defined(_WIN32)
    // Binary stdout so the response is exactly one JSON object plus \n. Text mode
    // would rewrite that to \r\n, and the mcp contract specifies \n.
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
#endif

    if (argc < 2) {
        // No arguments means a person opened the binary, most likely by double
        // clicking it, so a terminal gets the shell and stays there. Anything else is
        // something automated asking what this is, and it must get usage and an exit
        // rather than a prompt nobody is going to answer.
        if (re_shell_wanted(argc))
            return run_shell();
        print_usage();
        return re_err_exit_code(RE_E_USAGE);
    }
    const re_cmd_t *cmd = re_cmd_find(argv[1]);
    if (!cmd) {
        re_err_t err{};
        RE_ERR_SETF(&err, RE_E_USAGE, "unknown command '%s', try %s help", argv[1], kName);
        print_usage();
        return report_error(err);
    }
    if (re_str_eq_cstr(re_str(cmd->name), "help")) {
        print_usage();
        return 0;
    }
    if (re_str_eq_cstr(re_str(cmd->name), "version")) {
        std::fprintf(stderr, "%s %s schema %s\n", kName, kVersion, kSchema);
        return 0;
    }
    if (re_str_eq_cstr(re_str(cmd->name), "mcp"))
        return re_mcp_main();

    re_arena_t arena;
    re_arena_init(&arena, 256u * 1024u);
    re_err_t err{};
    err.code = RE_OK;
    re_ctx_t ctx{};
    ctx.arena = &arena;
    ctx.err = &err;
    int first = 0;
    if (!re_cmd_parse(&ctx, argc - 2, argv + 2, &first, &err)) {
        re_arena_free(&arena);
        return report_error(err);
    }
    const char *path = first < (argc - 2) ? argv[2 + first] : nullptr;
    if (!path) {
        re_arena_free(&arena);
        RE_ERR_SETF(&err, RE_E_USAGE, "%s needs a file, usage: %s", cmd->name, cmd->usage);
        return report_error(err);
    }
    int code = cmd->fn(&ctx, path, argc - 2 - first, argv + 2 + first);
    re_arena_free(&arena);
    return code;
}
