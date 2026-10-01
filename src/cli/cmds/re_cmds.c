// re_cmds.c - the command implementations behind the table. All read only.
// Module: cli (C11).
// Owns: per command JSON or text output, file loading, and the shared preamble.
// Depends: re_cmds.h, re_pe, re_format, re_strings, re_triage, re_json, re_text.
#include "cli/cmds/re_cmds.h"

#include <stdio.h>

#include "features/data/re_strings.h"
#include "features/data/re_triage.h"
#include "features/meta/re_features.h"
#include "features/pe/re_format.h"
#include "features/pe/re_pe.h"
#include "utils/algo/re_hash.h"
#include "utils/json/re_json.h"
#include "utils/mem/re_buf.h"
#include "utils/text/re_fmt.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_text.h"
#include "utils/text/re_util.h"
#include "cli/render/re_render.h"
#include "cli/render/re_report.h"

#define SCHEMA "antistrefo/1"

typedef struct {
    re_file_t file;
    re_span_t img;
    re_format_t fmt;
    re_pe_t pe;
    bool has_pe;
    re_strings_t strs;
} re_loaded_t;

// Returns a code, and records the human message in ctx->err. The split keeps the
// caller from having to copy a 200 byte record just to test success.
static re_err_code_t load(re_loaded_t *l, re_ctx_t *ctx, const char *path, bool need_pe,
                          bool need_str) {
    memset(l, 0, sizeof(*l));
    re_strings_init(&l->strs);
    re_err_code_t e = re_file_open(path, ctx->arena, &l->file);
    if (e != RE_OK) {
        RE_ERR_SETF(ctx->err, e, "cannot open %s", path);
        return e;
    }
    l->img = l->file.whole;
    l->fmt = re_format_detect(l->img);
    if (l->fmt == RE_FMT_UNKNOWN) {
        RE_ERR_SETF(ctx->err, RE_E_NOTBIN, "%s is not a recognized binary", path);
        return RE_E_NOTBIN;
    }
    if (l->fmt != RE_FMT_PE) {
        if (!need_pe)
            return RE_OK;
        RE_ERR_SETF(ctx->err, RE_E_UNSUPPORTED, "%s is %s, only pe is parsed in this build", path,
                    re_format_name(l->fmt));
        return RE_E_UNSUPPORTED;
    }
    e = re_pe_parse(l->img, ctx->arena, &l->pe);
    if (e != RE_OK)
        return e;
    l->has_pe = true;
    if (need_str) {
        re_strings_scan(l->img, 4, 20000, ctx->arena, &l->strs);
        re_strings_devices(l->img, 1024, ctx->arena, &l->strs);
        re_strings_pdb(l->img, ctx->arena, &l->strs);
    }
    return RE_OK;
}

static void unload(re_loaded_t *l) {
    re_file_close(&l->file);
}

static void preamble(re_jw_t *w, const char *tool, re_loaded_t *l) {
    re_jw_obj(w);
    re_jw_kcstr(w, "schema", SCHEMA);
    re_jw_kcstr(w, "tool", tool);
    re_jw_kcstr(w, "format", re_format_name(l->fmt));
    re_jw_ku64(w, "size", l->img.n);
}

static void finish(re_ctx_t *ctx, re_jw_t *w, re_loaded_t *l) {
    (void)ctx;
    (void)l;
    re_jw_obj_end(w);
    re_jw_flush(w, re_ctx_out(ctx));
}

int re_cmd_info(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (re_report_wanted(ctx))
        return re_render_info(ctx, path);
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "info", &l);
    re_jw_kcstr(&w, "arch", re_pe_machine_name(l.pe.machine));
    re_jw_kcstr(&w, "arch_hint", re_format_arch_hint(l.img, l.fmt));
    re_jw_kbool(&w, "pe32plus", l.pe.pe32plus);
    re_jw_kbool(&w, "is_dll", l.pe.is_dll);
    re_jw_kcstr(&w, "subsystem", re_pe_subsystem_name(l.pe.subsystem));
    re_jw_khex(&w, "image_base", l.pe.image_base, l.pe.pe32plus ? 16 : 8);
    re_jw_khex(&w, "entry_rva", l.pe.entry_rva, 8);
    re_jw_khex(&w, "entry_va", l.pe.image_base + l.pe.entry_rva, l.pe.pe32plus ? 16 : 8);
    re_jw_khex(&w, "timestamp", l.pe.timestamp, 8);
    re_jw_ku64(&w, "section_count", l.pe.n_sec);
    re_jw_ku64(&w, "import_modules", RE_VEC_LEN(&l.pe.imports));
    re_jw_ku64(&w, "import_symbols", RE_VEC_LEN(&l.pe.syms));
    re_jw_ku64(&w, "export_count", RE_VEC_LEN(&l.pe.exports));
    re_jw_key(&w, "features");
    re_jw_arr(&w);
    for (size_t i = 0; i < re_features_count(); i++) {
        const char *f = re_features_name(i);
        if (f)
            re_jw_cstr(&w, f);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_triage(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, true);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "triage", &l);
    re_jw_key(&w, "triage");
    re_jw_obj(&w);
    re_triage_emit(&w, l.img, &l.pe, &l.strs, ctx->arena);
    re_jw_obj_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

// Build one section row into caller supplied scratch, so the measure pass and the
// print pass share exactly the same cells and the columns line up.
static size_t section_cells(const re_pe_section_t *s, re_strbuf_t *flags, char va[16], char vs[24],
                            char rs[24], char en[16], const char *row[6]) {
    snprintf(va, 16, "0x%08x", s->vaddr);
    snprintf(vs, 24, "%llu", (unsigned long long)s->vsize);
    snprintf(rs, 24, "%llu", (unsigned long long)s->rsize);
    snprintf(en, 16, "%.3f", s->entropy);
    re_pe_section_flags(s->chars, flags);
    row[0] = s->name;
    row[1] = va;
    row[2] = vs;
    row[3] = rs;
    row[4] = en;
    row[5] = flags->p ? flags->p : "";
    return 6;
}

// The --format text path for sections. Split out so the command body stays under
// the function cap, and so the measure pass and the print pass share one helper.
static int sections_text(re_loaded_t *l, re_ctx_t *ctx) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, ctx->arena);
    // The flags go in their own buffer. Writing them into the accumulator would
    // leave row[] pointing into memory the row writer appends to, and the arena
    // reallocating under it, which is a dangling read and a hang.
    re_strbuf_t flags;
    re_strbuf_init(&flags, ctx->arena);
    char va[16];
    char vs[24];
    char rs[24];
    char en[16];
    const char *row[6];
    re_text_t t;
    re_text_init(&t, &sb);
    for (uint16_t i = 0; i < l->pe.n_sec; i++) {
        size_t n = section_cells(&l->pe.sec[i], &flags, va, vs, rs, en, row);
        re_text_measure(&t, row, n);
    }
    const char *hdr[6] = {"name", "vaddr", "vsize", "raw", "entropy", "flags"};
    re_text_header(&t, hdr, 6);
    for (uint16_t i = 0; i < l->pe.n_sec; i++) {
        size_t n = section_cells(&l->pe.sec[i], &flags, va, vs, rs, en, row);
        re_text_row(&t, row, n);
    }
    fputs(sb.p ? sb.p : "", stdout);
    return 0;
}

int re_cmd_sections(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    if (re_report_wanted(ctx))
        return re_render_sections(ctx, path);
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_strbuf_t sb;
    re_strbuf_init(&sb, ctx->arena);
    if (ctx->out == RE_FMT_OUT_TEXT) {
        sections_text(&l, ctx);
        unload(&l);
        return 0;
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "sections", &l);
    re_jw_ku64(&w, "count", l.pe.n_sec);
    re_jw_key(&w, "sections");
    re_jw_arr(&w);
    for (uint16_t i = 0; i < l.pe.n_sec; i++) {
        const re_pe_section_t *s = &l.pe.sec[i];
        re_jw_obj(&w);
        re_jw_kcstr(&w, "name", s->name);
        re_jw_khex(&w, "vaddr", s->vaddr, 8);
        re_jw_ku64(&w, "vsize", s->vsize);
        re_jw_ku64(&w, "raw_size", s->rsize);
        re_jw_khex(&w, "raw_ptr", s->rptr, 8);
        re_jw_kf64(&w, "entropy", s->entropy);
        re_jw_kbool(&w, "packed", s->entropy > 7.0);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_imports(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    if (re_report_wanted(ctx))
        return re_render_imports(ctx, path);
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "imports", &l);
    re_jw_ku64(&w, "module_count", RE_VEC_LEN(&l.pe.imports));
    re_jw_ku64(&w, "symbol_count", RE_VEC_LEN(&l.pe.syms));
    re_jw_key(&w, "modules");
    re_jw_arr(&w);
    size_t seen = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&l.pe.imports); i++) {
        const re_pe_imp_t *im = RE_VEC_PTR(&l.pe.imports, re_pe_imp_t, i);
        re_jw_obj(&w);
        re_jw_kstr(&w, "module", im->dll);
        re_jw_key(&w, "symbols");
        re_jw_arr(&w);
        for (uint32_t k = 0; k < im->n_syms; k++) {
            if (ctx->offset && seen++ < ctx->offset)
                continue;
            if (ctx->limit && seen - ctx->offset >= ctx->limit)
                break;
            const re_str_t *s = RE_VEC_PTR(&l.pe.syms, re_str_t, im->first_sym + k);
            re_jw_str(&w, *s);
        }
        re_jw_arr_end(&w);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_exports(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, true, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "exports", &l);
    re_jw_ku64(&w, "count", RE_VEC_LEN(&l.pe.exports));
    re_jw_key(&w, "exports");
    re_jw_arr(&w);
    size_t seen = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&l.pe.exports); i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&l.pe.exports, re_pe_exp_t, i);
        if (ctx->offset && seen++ < ctx->offset)
            continue;
        if (ctx->limit && seen - ctx->offset >= ctx->limit)
            break;
        re_jw_obj(&w);
        re_jw_kstr(&w, "name", x->name);
        re_jw_ku64(&w, "ordinal", x->ordinal);
        re_jw_ku64(&w, "rva", x->rva);
        re_jw_obj_end(&w);
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_strings(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, false, true);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_rx_t *rx = NULL;
    if (ctx->has_regex) {
        char *pat = re_arena_strndup(ctx->arena, ctx->regex.p, ctx->regex.n);
        rx = re_rx_compile(ctx->arena, pat, "i", ctx->err);
        if (!rx) {
            unload(&l);
            return re_err_exit_code(ctx->err->code);
        }
    }
    re_vec_t hits;
    re_vec_init(&hits, sizeof(re_str_hit_t));
    size_t matched = RE_VEC_LEN(&l.strs.hits);
    if (rx)
        matched = re_strings_filter(ctx->arena, &l.strs, rx, ctx->offset, ctx->limit, &hits);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "strings", &l);
    re_jw_ku64(&w, "total", matched);
    re_jw_ku64(&w, "count", RE_VEC_LEN(&hits));
    re_jw_kbool(&w, "truncated", matched > RE_VEC_LEN(&hits));
    re_jw_key(&w, "strings");
    re_jw_arr(&w);
    if (rx) {
        for (size_t i = 0; i < RE_VEC_LEN(&hits); i++) {
            const re_str_hit_t *h = RE_VEC_PTR(&hits, re_str_hit_t, i);
            re_jw_obj(&w);
            re_jw_khex(&w, "off", h->off, 8);
            re_jw_kbool(&w, "wide", h->wide);
            re_jw_kstr(&w, "text", h->text);
            re_jw_obj_end(&w);
        }
    } else {
        size_t seen = 0;
        for (size_t i = 0; i < RE_VEC_LEN(&l.strs.hits); i++) {
            if (ctx->offset && seen++ < ctx->offset)
                continue;
            if (ctx->limit && seen - ctx->offset >= ctx->limit)
                break;
            const re_str_hit_t *h = RE_VEC_PTR(&l.strs.hits, re_str_hit_t, i);
            re_jw_obj(&w);
            re_jw_khex(&w, "off", h->off, 8);
            re_jw_kbool(&w, "wide", h->wide);
            re_jw_kstr(&w, "text", h->text);
            re_jw_obj_end(&w);
        }
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

int re_cmd_hexdump(re_ctx_t *ctx, const char *path, int argc, char **argv) {
    (void)argc;
    (void)argv;
    re_loaded_t l;
    re_err_code_t e = load(&l, ctx, path, false, false);
    if (e != RE_OK) {
        unload(&l);
        return re_err_exit_code(e);
    }
    re_span_t view = re_span_sub(l.img, ctx->off, ctx->len);
    if (!re_span_valid(view))
        view = re_span_sub(l.img, ctx->off, l.img.n - ctx->off);
    re_jw_t w;
    re_jw_init(&w, ctx->arena);
    preamble(&w, "hexdump", &l);
    re_jw_khex(&w, "off", ctx->off, 8);
    re_jw_ku64(&w, "len", view.n);
    re_jw_key(&w, "bytes");
    re_jw_arr(&w);
    for (size_t i = 0; i < view.n; i += 16) {
        re_strbuf_t line;
        re_strbuf_init(&line, ctx->arena);
        re_strbuf_put_hex(&line, view.p + i, view.n - i > 16 ? 16 : view.n - i);
        re_jw_str(&w, re_strn(line.p, line.len));
    }
    re_jw_arr_end(&w);
    finish(ctx, &w, &l);
    unload(&l);
    return 0;
}

// Where a command's response goes. NULL in the context means stdout, which is every
// caller except the MCP server. The indirection exists so the server can capture a
// response instead of printing it, without every command learning about protocols.
void *re_ctx_out(const re_ctx_t *ctx) {
    return ctx->stream ? ctx->stream : stdout;
}
