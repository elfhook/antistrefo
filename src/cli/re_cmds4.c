// re_cmds4.c - the decompiler command.
// Module: cli (C11).
// Owns: the decompile command, which renders one function as C-like source.
// Depends: re_prep, re_decompile, re_dc_walk, re_func, re_stack, re_xref, re_json.
// Depends: re_decompile, re_dc_walk, re_func, re_stack, re_xref, re_prep.
#include "cli/re_cmds3.h"

#include "features/re_decompile.h"
#include "features/re_func.h"
#include "features/re_stack.h"
#include "features/re_xref.h"
#include "utils/re_json.h"
#include "utils/re_strbuf.h"
#include "cli/re_prep.h"

// The function the command works on: the one containing the address given, or the
// function at the entry point when no address was given. A function subject is
// resolved here so the command answers the question a reader actually asked, which
// is "show me this function", not "show me these bytes".
static bool pick_func(re_ctx_t *ctx, const re_fscan_t *scan, const re_pe_t *pe, const char *pos,
                      const re_func_t **out) {
    uint64_t at = 0;
    long fi;
    if (pos) {
        if (!re_parse_addr(ctx, re_str(pos), pe, &at))
            return false;
    } else {
        if (!pe->entry_rva) {
            RE_ERR_SET(ctx->err, RE_E_MALFORMED, "no entry point, pass an address");
            return false;
        }
        at = pe->image_base + pe->entry_rva;
    }
    fi = re_func_index_of(scan, at);
    if (fi < 0) {
        RE_ERR_SETF(ctx->err, RE_E_USAGE, "no function at 0x%llx", (unsigned long long)at);
        return false;
    }
    *out = re_func_at(scan, (size_t)fi);
    return true;
}

int re_cmd_decompile(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_decomp_t d;
    re_stack_t st;
    re_strbuf_t text;
    const re_func_t *fn = NULL;
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    if (!pick_func(ctx, &scan, &pe, re_cmd_positional(argc, argv, 1), &fn)) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    // The xref set is what turns a call target into an imported name, so the emitter
    // gets it. Without it every call would print as a bare address.
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    re_stack_analyze(&code, fn, ctx->arena, &st);
    d.code = &code;
    d.xrefs = &xs;
    d.arena = ctx->arena;
    re_strbuf_init(&text, ctx->arena);
    bool ok = re_decompile_ok(&d, fn);
    if (ok)
        re_decompile_func(&d, fn, &st, &text);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    re_envelope(&w, "decompile", f.whole, &pe);
    re_jw_khex(&w, "va", fn->va, 16);
    re_jw_ku64(&w, "rva", fn->rva);
    re_jw_ku64(&w, "size", fn->size);
    re_jw_kcstr(&w, "cc", re_cc_name(st.cc));
    re_jw_ku64(&w, "params", st.n_params);
    re_jw_ku64(&w, "locals", st.n_locals);
    re_jw_kbool(&w, "ok", ok);
    if (fn->name.n)
        re_jw_kstr(&w, "name", fn->name);
    // Only the fields a reader acts on: the source, and the strings it touches,
    // which name the function far better than the source alone does.
    re_jw_kstr(&w, "source", re_str(text.p ? text.p : ""));
    re_vec_t strs;
    re_vec_init(&strs, sizeof(uint32_t));
    re_jw_ku64(&w, "strings", re_xref_func_strings(&xs, fn, ctx->arena, &strs));
    re_vec_truncate(&strs, 0);
    re_jw_obj_end(&w);
    re_jw_flush(&w, stdout);
    re_file_close(&f);
    return 0;
}
