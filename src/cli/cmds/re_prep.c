// re_prep.c - the shared preamble of the code reading commands.
// Module: cli (C11).
// Owns: opening, parsing, and the JSON envelope. Nothing here knows a command.
// Depends: re_prep.h.
#include "cli/cmds/re_prep.h"

#include "features/analysis/re_analyze.h"
#include "features/data/re_gopath.h"
#include "features/lib/re_sigfile.h"
#include "features/pe/re_format.h"
#include "utils/text/re_hex.h"

bool re_prepare(re_ctx_t *ctx, const char *path, re_file_t *f, re_pe_t *pe, re_code_t *code) {
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
    // The arch is looked up rather than assumed, so a build with no backend fails
    // with a clear message here instead of dereferencing a null vtable further on.
    const re_disasm_t *d = re_disasm_find("x86-64");
    if (!re_code_init(code, f->whole, pe, d, ctx->arena)) {
        RE_ERR_SET(ctx->err, RE_E_UNSUPPORTED, "no x86-64 disassembler in this build");
        return false;
    }
    return true;
}

void re_envelope(re_jw_t *w, const char *tool, re_span_t img, const re_pe_t *pe) {
    // A single backend exists, so this is the first arch rather than a lookup. It
    // stays honest because re_code_init would have failed without a vtable.
    const char *arch = re_disasm_arch_count() > 0 ? re_disasm_arch_name(0) : "none";
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", RE_SCHEMA);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(re_format_detect(img)));
    re_jw_kcstr(w, "arch", arch);
    re_jw_ku64(w, "size", img.n);
    re_jw_ku64(w, "image_base", pe->image_base);
}

// The names the image states about itself, before any pattern is consulted. A Go binary
// lists every function it contains and what each is called, which is evidence a signature
// cannot produce, and the signature pass below leaves those functions alone. A file with
// no such table costs one search and no names.
static size_t name_from_image(re_ctx_t *ctx, re_code_t *code, re_fscan_t *scan) {
    re_vec_t syms;
    re_goinfo_t info;
    uint64_t lo = 0;
    uint64_t hi = 0;
    re_vec_init(&syms, sizeof(re_gosym_t));
    re_code_window(code, &lo, &hi);
    if (!re_gopath_scan(code->img, lo, hi, code->base + code->pe->entry_rva, ctx->arena, &syms,
                        &info))
        return 0;
    return re_symbols_apply(scan, &syms);
}

size_t re_prep_names(re_ctx_t *ctx, const char *sigfile, re_code_t *code, re_fscan_t *scan,
                     re_flirt_load_stat_t *stat) {
    re_vec_t sigs;
    re_sigdb_t db;
    size_t named = name_from_image(ctx, code, scan);
    if (stat) {
        stat->before = 0;
        stat->loaded = 0;
        stat->rejected = 0;
        stat->skipped = 0;
    }
    re_vec_init(&sigs, sizeof(re_sig_t));
    re_flirt_builtin(ctx->arena, &sigs);
    if (sigfile)
        re_sigfile_load(ctx->arena, sigfile, &sigs, stat);
    re_sigdb_build(ctx->arena, &sigs, &db);
    return named + re_flirt_name_all(&db, code, scan);
}

bool re_parse_addr(re_ctx_t *ctx, re_str_t s, const re_pe_t *pe, uint64_t *out) {
    uint64_t acc = 0;
    uint64_t mul = 10;
    size_t i = 0;
    if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
        mul = 16;
        i = 2;
    }
    if (i >= s.n) {
        RE_ERR_SET(ctx->err, RE_E_USAGE, "expected an address");
        return false;
    }
    for (; i < s.n; i++) {
        int d = re_hex_val(s.p[i]);
        if (d < 0 || (uint64_t)d >= mul) {
            RE_ERR_SETF(ctx->err, RE_E_USAGE, "cannot read an address from %s", s.p);
            return false;
        }
        acc = acc * mul + (uint64_t)d;
    }
    bool in_image = acc >= pe->image_base && (acc - pe->image_base) < pe->size_of_image;
    *out = in_image ? acc : pe->image_base + acc;
    return true;
}
