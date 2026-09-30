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
#include "features/re_xref.h"
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

// The flags a reference carries, as names. Same reasoning as the function flags:
// a reader should not have to know which bit means import.
static void emit_ref_flags(re_jw_t *w, uint8_t flags) {
    static const struct {
        uint8_t bit;
        const char *name;
    } kNames[] = {
        {RE_XRF_CODE, "code"},     {RE_XRF_IMPORT, "import"}, {RE_XRF_EXPORT, "export"},
        {RE_XRF_STRING, "string"}, {RE_XRF_DATA, "data"},     {RE_XRF_OUTSIDE, "outside"},
        {RE_XRF_JTABLE, "jtable"},
    };
    re_jw_key(w, "flags");
    re_jw_arr(w);
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        if (flags & kNames[i].bit)
            re_jw_str(w, re_str(kNames[i].name));
    }
    re_jw_arr_end(w);
}

// Accepts a decimal or 0x hex address, as an RVA or already absolute. A value
// that falls inside the image is taken as a virtual address and anything else as
// an RVA. Guessing by magnitude does not work here: a driver mapped at 0x10000
// has virtual addresses around 0x11000, which are just as small as the RVAs.
static bool parse_addr(re_ctx_t *ctx, re_str_t s, const re_pe_t *pe, uint64_t *out) {
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

static const char *kind_name(uint8_t k) {
    switch (k) {
        case RE_XR_CALL:
            return "call";
        case RE_XR_JUMP:
            return "jump";
        case RE_XR_COND:
            return "cond";
        default:
            return "data";
    }
}

static void emit_ref(re_jw_t *w, const re_xref_t *r, long func_index) {
    re_jw_obj(w);
    re_jw_khex(w, "from", r->from, 16);
    re_jw_khex(w, "to", r->to, 16);
    re_jw_ku64(w, "rva", r->rva);
    re_jw_kcstr(w, "kind", kind_name(r->kind));
    if (r->name.n)
        re_jw_kstr(w, "name", r->name);
    if (func_index >= 0)
        re_jw_ku64(w, "func", (uint64_t)func_index);
    emit_ref_flags(w, r->flags);
    re_jw_obj_end(w);
}

// Emit one direction of the answer. A function is queried by its body, because
// the instructions that make the references are spread through it; anything else
// is an exact address. indices holds the fwd indices when the subject is a
// function and is ignored otherwise.
static void emit_side(re_jw_t *w, const re_xrefset_t *xs, const re_fscan_t *scan, const char *key,
                      bool from_side, uint64_t subject, uint64_t span, const re_vec_t *indices) {
    // The count comes from the range query when there is a range, and from the
    // exact lookup otherwise, so a non function subject still reports its own
    // references rather than silently reporting none.
    size_t n = span ? RE_VEC_LEN(indices)
                    : (from_side ? re_xref_from_count(xs, subject) : re_xref_to_count(xs, subject));
    re_jw_key(w, key);
    re_jw_arr(w);
    for (size_t i = 0; i < n; i++) {
        const re_xref_t *r = NULL;
        if (span)
            r = RE_VEC_PTR(&xs->fwd, re_xref_t, RE_VEC_AT(indices, uint32_t, i));
        else
            r = from_side ? re_xref_from_at(xs, subject, i) : re_xref_to_at(xs, subject, i);
        if (r)
            emit_ref(w, r, re_func_index_of(scan, from_side ? r->to : r->from));
    }
    re_jw_arr_end(w);
}

// The subject is one address, given as an RVA or a virtual address. xrefs to it
// are the question worth asking, and the callers are the useful part of the
// answer, so both directions come back.
int re_cmd_xrefs(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_vec_t into;
    re_vec_t outof;
    re_str_t want = re_str("");
    uint64_t subject = 0;
    uint64_t span = 0;
    // argv[0] is the file, which main already passed as path, so an address is
    // the second argument. With only the file there is nothing to look up.
    bool have = argc >= 2;
    if (!prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    if (have)
        want = re_str(argv[1]);
    re_func_scan(&code, ctx->arena, &scan);
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    if (have && !parse_addr(ctx, want, &pe, &subject)) {
        re_file_close(&f);
        return re_err_exit_code(RE_E_USAGE);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    envelope(&w, "xrefs", f.whole, &pe);
    re_jw_ku64(&w, "refs", RE_VEC_LEN(&xs.fwd));
    re_jw_ku64(&w, "indirect", xs.n_indirect);
    if (!have) {
        re_jw_ku64(&w, "total", RE_VEC_LEN(&xs.fwd));
        re_jw_kbool(&w, "truncated", false);
        re_jw_obj_end(&w);
        re_jw_flush(&w, stdout);
        re_file_close(&f);
        return 0;
    }
    long fi = re_func_index_of(&scan, subject);
    re_jw_khex(&w, "subject", subject, 16);
    re_jw_ku64(&w, "subject_rva", subject - code.base);
    if (fi >= 0) {
        span = re_func_at(&scan, (size_t)fi)->size;
        re_jw_ku64(&w, "subject_func", (uint64_t)fi);
    }
    re_vec_init(&into, sizeof(uint32_t));
    re_vec_init(&outof, sizeof(uint32_t));
    if (span) {
        re_xref_into(&xs, ctx->arena, subject, span, 0, &into);
        re_xref_out_of(&xs, ctx->arena, subject, span, 0, &outof);
    }
    emit_side(&w, &xs, &scan, "called_from", false, subject, span, &into);
    emit_side(&w, &xs, &scan, "refers_to", true, subject, span, &outof);
    re_jw_ku64(&w, "total", RE_VEC_LEN(&into) + RE_VEC_LEN(&outof));
    re_jw_kbool(&w, "truncated", false);
    re_jw_obj_end(&w);
    re_jw_flush(&w, stdout);
    re_file_close(&f);
    return 0;
}
