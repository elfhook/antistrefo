// re_render2.c - the framed reports for the analysis commands.
// Module: cli (C11).
// Owns: the text rendering of cfg and regions.
// Depends: re_render2.h, re_prep, re_report, re_cfg, re_regions, re_tui. Reads the
//           same feature APIs the JSON path reads; never a second source of truth.
#include "cli/render/re_render2.h"

#include "features/code/re_func.h"
#include "features/data/re_regions.h"
#include "features/dec/re_cfg.h"
#include "utils/mem/re_vec.h"
#include "utils/sys/re_path.h"
#include "utils/text/re_strbuf.h"
#include "utils/tui/re_tui.h"
#include "cli/cmds/re_prep.h"
#include "cli/render/re_report.h"

// Defined below, used above: the successor column is part of the block table.
static const char *successors(re_report_t *r, const re_cfg_t *g, size_t from);

// The function to draw, chosen by address when one was given and otherwise the first
// the scan found. A renderer is reached without argv, so the address arrives as an
// argument; the same lookup the JSON path uses is here so both agree on the subject.
static const re_func_t *cfg_subject(re_ctx_t *ctx, const re_fscan_t *scan, const re_pe_t *pe,
                                    const char *addr) {
    long idx = 0;
    if (addr) {
        uint64_t va = 0;
        if (!re_parse_addr(ctx, re_str(addr), pe, &va))
            return NULL;
        idx = re_func_index_of(scan, va);
        if (idx < 0) {
            RE_ERR_SETF(ctx->err, RE_E_USAGE, "no function at 0x%llx", (unsigned long long)va);
            return NULL;
        }
    }
    return re_func_at(scan, (size_t)idx);
}

// cfg: one row per basic block, then the successors. The terminator column is the
// point of the table: a reader scanning the graph wants to know why each block stops
// before they want to know how big it was.
// The block table itself. The terminator column is the reason this table is worth
// printing: a reader scanning the graph wants to know why each block stops before
// they want to know how big it was.
static void cfg_table(re_report_t *r, const re_cfg_t *g) {
    re_table_t tt;
    static const size_t kWidths[7] = {5, 16, 7, 7, 10, 12, 0};
    const char *cols[7] = {"blk", "va", "size", "insns", "term", "succ", ""};
    const char *cells[7];
    re_table_begin(&tt, r, "Basic blocks", kWidths, 7);
    re_table_head(&tt, cols);
    for (size_t i = 0; i < RE_VEC_LEN(&g->blocks); i++) {
        const re_cfg_block_t *b = RE_VEC_PTR(&g->blocks, re_cfg_block_t, i);
        cells[0] = re_report_tmp(r, "%zu", i);
        cells[1] = re_report_tmp(r, "0x%llx", (unsigned long long)b->va);
        cells[2] = re_report_tmp(r, "%u", b->size);
        cells[3] = re_report_tmp(r, "%u", b->n_insns);
        cells[4] = re_cfg_term_name(b->term);
        cells[5] = successors(r, g, i);
        cells[6] = "";
        re_table_row(&tt, cells);
    }
    re_table_end(&tt);
}

int re_render_cfg(re_ctx_t *ctx, const char *path, const char *addr) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_cfg_t g;
    const re_func_t *fn = NULL;
    re_report_t r;
    re_strbuf_t subj;
    re_strbuf_t sum;
    const char *tabs[1] = {"control flow"};
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    fn = cfg_subject(ctx, &scan, &pe, addr);
    if (!fn) {
        re_file_close(&f);
        return re_err_exit_code(ctx->err->code);
    }
    bool ok = re_cfg_build(&code, fn, &g, ctx->arena);
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    re_strbuf_puts(&subj, "cfg ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&subj, " 0x%llx", (unsigned long long)fn->va);
    if (ok)
        re_strbuf_appendf(&sum, "%zu blocks  %zu edges", RE_VEC_LEN(&g.blocks),
                          RE_VEC_LEN(&g.edges));
    else
        re_strbuf_puts(&sum, "no blocks recovered");
    re_report_head(&r, subj.p, sum.p);
    // What the analysis could not settle is reported next to what it could, because a
    // graph that silently omits its uncertain parts reads as complete.
    if (g.n_unknown || g.n_unresolved || g.truncated)
        re_report_note(&r, RE_ST_WARN,
                       re_report_tmp(&r,
                                     "%u block terminators unclassified, %u unresolved "
                                     "edges%s",
                                     g.n_unknown, g.n_unresolved,
                                     g.truncated ? ", graph truncated at the block cap" : ""));
    cfg_table(&r, &g);
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}

// The successors of one block, as short arrows. A tail call has no destination inside
// the function, so it prints as an arrow to nowhere rather than as a missing index.
static const char *successors(re_report_t *r, const re_cfg_t *g, size_t from) {
    re_strbuf_t sb;
    bool first = true;
    re_strbuf_init(&sb, r->scratch.arena);
    for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
        const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
        if (e->from != from)
            continue;
        if (!first)
            re_strbuf_puts(&sb, " ");
        first = false;
        if (e->kind == RE_CFG_EDGE_TAIL || e->to < 0) {
            re_strbuf_puts(&sb, "->ext");
            continue;
        }
        re_strbuf_putc(&sb, e->kind == RE_CFG_EDGE_TAKEN ? 'T' : 'F');
        re_strbuf_appendf(&sb, "%d", e->to);
    }
    if (first)
        re_strbuf_puts(&sb, "-");
    return re_report_tmp(r, "%s", sb.p ? sb.p : "-");
}

// regions: one row per window with the counts the verdict came from, so a reader who
// disagrees with the rule can still use the evidence. Confidence is its own column
// rather than folded into the kind, because "data, low" and "data, high" are very
// different things to act on.
int re_render_regions(re_ctx_t *ctx, const char *path) {
    re_file_t f;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    re_vec_t out;
    bool truncated = false;
    re_report_t r;
    re_table_t tt;
    re_strbuf_t subj;
    re_strbuf_t sum;
    static const size_t kWidths[9] = {14, 8, 8, 8, 7, 7, 7, 7, 0};
    const char *tabs[1] = {"regions"};
    const char *cols[9] = {"rva", "kind", "conf", "section", "fns", "bytes", "refs", "jt", ""};
    const char *cells[9];
    if (!re_prepare(ctx, path, &f, &pe, &code))
        return re_err_exit_code(ctx->err->code);
    re_func_scan(&code, ctx->arena, &scan);
    re_xref_build(&code, &scan, &pe, ctx->arena, &xs);
    re_vec_init(&out, sizeof(re_region_t));
    re_region_scan(&code, &scan, &xs, &pe, 4096, &out, &truncated, ctx->arena);
    re_report_open(&r, ctx->arena, ctx, tabs, 1);
    re_strbuf_init(&subj, ctx->arena);
    re_strbuf_init(&sum, ctx->arena);
    re_strbuf_puts(&subj, "regions ");
    re_strbuf_puts(&subj, re_path_basename_ptr(path));
    re_strbuf_appendf(&sum, "%zu windows of 4096", RE_VEC_LEN(&out));
    re_report_head(&r, subj.p, sum.p);
    re_table_begin(&tt, &r, "Code versus data", kWidths, 9);
    re_table_head(&tt, cols);
    for (size_t i = 0; i < RE_VEC_LEN(&out) && i < ctx->limit; i++) {
        const re_region_t *g = RE_VEC_PTR(&out, re_region_t, i);
        cells[0] = re_report_tmp(&r, "0x%llx", (unsigned long long)g->rva);
        cells[1] = re_reg_kind_name(g->kind);
        cells[2] = re_reg_conf_name(g->confidence);
        cells[3] = g->sec[0] ? g->sec : "-";
        cells[4] = re_report_tmp(&r, "%u", g->n_funcs);
        cells[5] = re_report_tmp(&r, "%u", g->func_bytes);
        cells[6] = re_report_tmp(&r, "%u", g->n_data_refs);
        cells[7] = re_report_tmp(&r, "%u", g->n_jtables);
        cells[8] = "";
        re_table_row(&tt, cells);
    }
    re_table_end(&tt);
    if (truncated)
        re_report_note(&r, RE_ST_WARN, "region list truncated");
    re_report_end(&r);
    re_file_close(&f);
    return 0;
}
