// re_cmds3.c - the disassembly surface: functions, disassembly, and xrefs.
// Module: cli (C11).
// Owns: the funcs, disasm and xrefs commands, and the code map they share.
// Depends: re_code, re_func, re_xref, re_disasm. One JSON object on stdout.
#include "cli/re_cmds3.h"

#include "features/re_code.h"
#include "features/re_disasm.h"
#include "features/re_format.h"
#include "features/re_func.h"
#include "features/re_pe.h"
#include "utils/re_json.h"
#include "utils/re_strbuf.h"

#define SCHEMA3 "antistrefo/1"

// The architecture name the code map was built for. A single backend exists in
// task 3, so this is the first one rather than a lookup, and it stays honest
// because the map would have failed to initialise without it.
static const char *arch_name(void) {
    return re_disasm_arch_count() > 0 ? re_disasm_arch_name(0) : "none";
}

// Open the file, parse the PE, and stand up the code map. Everything the three
// commands need comes from here, so a failure is reported once with one message.
static bool prepare(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code) {
    re_err_code_t e = re_file_open(path, ctx->arena, f);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return false;
    }
    e = re_pe_parse(f->whole, ctx->arena, pe);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot parse %s", path);
        return false;
    }
    const re_disasm_t *d = re_disasm_find("x86-64");
    if (!re_code_init(code, f->whole, pe, d, ctx->arena)) {
        RE_ERR_SET(ctx->err, RE_E_UNSUPPORTED, "no x86-64 disassembler in this build");
        return false;
    }
    return true;
}

static void envelope(re_jw_t *w, const char *tool, re_span_t img, const re_pe_t *pe) {
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", SCHEMA3);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(re_format_detect(img)));
    re_jw_kcstr(w, "arch", arch_name());
    re_jw_ku64(w, "size", img.n);
    re_jw_ku64(w, "image_base", pe->image_base);
}

// The flags a function carries, as names rather than a bitmask, because a caller
// reading this should not have to know which bit means prologue.
static void emit_flags(re_jw_t *w, uint32_t flags) {
    static const struct {
        uint32_t bit;
        const char *name;
    } kNames[] = {
        {RE_FUNC_ENTRY, "entry"},          {RE_FUNC_EXPORT, "export"},
        {RE_FUNC_PROLOGUE, "prologue"},    {RE_FUNC_FLIRT, "flirt"},
        {RE_FUNC_THUNK, "thunk"},          {RE_FUNC_NORETURN, "noreturn"},
        {RE_FUNC_OVERLAP, "overlap"},      {RE_FUNC_EXTERNAL, "calls_outside"},
        {RE_FUNC_JTABLE, "indirect_jump"}, {RE_FUNC_RET, "returns"},
    };
    re_jw_key(w, "flags");
    re_jw_arr(w);
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        if (flags & kNames[i].bit)
            re_jw_str(w, re_str(kNames[i].name));
    }
    re_jw_arr_end(w);
}

static void emit_func(re_jw_t *w, const re_func_t *f, size_t edges) {
    re_jw_obj(w);
    re_jw_khex(w, "va", f->va, 16);
    re_jw_ku64(w, "rva", f->rva);
    re_jw_ku64(w, "size", f->size);
    re_jw_ku64(w, "insns", f->n_insns);
    re_jw_ku64(w, "frame", f->frame_size);
    re_jw_ku64(w, "calls", f->n_calls);
    re_jw_ku64(w, "jumps", f->n_jumps);
    re_jw_ku64(w, "out_edges", edges);
    emit_flags(w, f->flags);
    re_jw_obj_end(w);
}

int re_cmd_funcs(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    (void)argc;
    (void)argv;
    if (!prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "funcs", f.whole, &pe);
    re_jw_key(&w, "functions");
    re_jw_arr(&w);
    size_t shown = 0;
    size_t total = RE_VEC_LEN(&scan.funcs);
    for (size_t i = ctx->offset; i < total && shown < ctx->limit; i++, shown++) {
        const re_func_t *fn = re_func_at(&scan, i);
        emit_func(&w, fn, re_func_edge_count(&scan, fn));
    }
    re_jw_arr_end(&w);
    re_jw_ku64(&w, "total", total);
    re_jw_kbool(&w, "truncated", shown < total);
    re_jw_ku64(&w, "edges", RE_VEC_LEN(&scan.edges));
    re_jw_obj_end(&w);
    re_jw_flush(&w, stdout);
    re_file_close(&f);
    return 0;
}
