// re_prep.c - the shared preamble of the code reading commands.
// Module: cli (C11).
// Owns: opening, parsing, and the JSON envelope. Nothing here knows a command.
// Depends: re_prep.h.
#include "cli/re_prep.h"

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
