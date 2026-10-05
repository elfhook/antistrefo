// re_score.c - measures the six analysis axes over one analysed file.
// Module: feature (C11).
// Owns: the sampling, the counting, and the composite.
// Depends: re_score.h, re_cfg, re_flow, re_ir, re_disasm. Nothing here re-runs a
//           pass: every count comes off structures the analysis already built.
#include "features/analysis/re_score.h"

#include "features/dec/re_cfg.h"
#include "features/dec/re_ir.h"
#include "features/flow/re_flow.h"
#include "features/meta/re_disasm.h"

#include <string.h>

// The exception table against the walk. An entry counts only when a recovered
// function starts exactly where the compiler said, because a function that merely
// contains the stated start is the walk disagreeing with the image, not agreeing.
static size_t pdata_hits(const re_pe_t *pe, const re_fscan_t *scan) {
    size_t hit = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&pe->unwind); i++) {
        const re_pe_unwind_t *u = RE_VEC_PTR(&pe->unwind, re_pe_unwind_t, i);
        uint64_t va = pe->image_base + u->begin;
        long idx = re_func_index_of(scan, va);
        if (idx >= 0 && re_func_at(scan, (size_t)idx)->va == va)
            hit++;
    }
    return hit;
}

// Edge resolution over the sample. A tail call is a resolved outcome - control
// demonstrably left the function for a stated reason - so it is not an unresolved
// edge; everything else with no destination is.
static void edge_sample(re_code_t *code, const re_fscan_t *scan, const re_vec_t *jtables,
                        re_arena_t *a, re_score_t *out) {
    size_t n = RE_VEC_LEN(&scan->funcs);
    if (n > RE_SCORE_SAMPLE)
        n = RE_SCORE_SAMPLE;
    for (size_t i = 0; i < n; i++) {
        re_cfg_t g;
        if (!re_cfg_build(code, re_func_at(scan, i), &g, a))
            continue;
        // A dispatch the scan bound to a jump table is a resolved edge, not a dead
        // end: the decompiler sees the same binding, so the scoreboard and the
        // printed pseudocode describe one graph rather than two.
        re_flow_cfg_jtables(&g, code, jtables, a);
        out->n_edges += RE_VEC_LEN(&g.edges);
        out->n_edges_ok += RE_VEC_LEN(&g.edges) - g.n_unresolved;
    }
}

// Call naming. A target is named when the xref index says import or export, or
// when the function record it lands on carries a name of any provenance - export,
// signature, Go table, or a seed's j_ thunk. An unnamed recovered target counts
// as a call that resolved but did not name, which is the honest middle outcome.
static void call_stats(const re_xrefset_t *xs, const re_fscan_t *scan, re_score_t *out) {
    for (size_t i = 0; i < RE_VEC_LEN(&xs->fwd); i++) {
        const re_xref_t *r = RE_VEC_PTR(&xs->fwd, re_xref_t, i);
        if (r->kind != RE_XR_CALL)
            continue;
        out->n_calls++;
        if (r->flags & (RE_XRF_IMPORT | RE_XRF_EXPORT)) {
            out->n_calls_named++;
            continue;
        }
        long idx = re_func_index_of(scan, r->to);
        if (idx >= 0 && re_func_at(scan, (size_t)idx)->name.n)
            out->n_calls_named++;
    }
}

// Lowering coverage. Every instruction of the sampled functions goes through the
// arch's own lower hook exactly as the decompiler drives it, so the number the
// scoreboard prints is the number the pseudocode will show. A function stops
// being measured when its temporaries run low, because past that point the
// lowering would refuse for reasons that say nothing about the instruction.
static void lower_sample(re_code_t *code, const re_fscan_t *scan, re_arena_t *a, re_score_t *out) {
    const re_disasm_t *dis = code->dis;
    size_t n = RE_VEC_LEN(&scan->funcs);
    if (!dis || !dis->lower)
        return;
    if (n > RE_SCORE_SAMPLE)
        n = RE_SCORE_SAMPLE;
    for (size_t i = 0; i < n && out->n_insns < RE_SCORE_INSN_BUDGET; i++) {
        const re_func_t *f = re_func_at(scan, i);
        re_ir_func_t ir;
        uint64_t va = f->va;
        uint64_t end = f->va + f->size;
        uint32_t taken = 0;
        re_ir_func_init(&ir);
        if (!re_ir_block_begin(&ir, a, f->va, f->size))
            continue;
        while (va < end && taken < RE_SCORE_FUNC_INSNS && out->n_insns < RE_SCORE_INSN_BUDGET) {
            re_insn_t in;
            size_t before = ir.n_blocks ? ir.blocks[ir.n_blocks - 1].n_ops : 0;
            size_t after;
            if (!re_code_insn(code, va, &in) || in.size == 0)
                break;
            dis->lower(dis->ctx, &in, &ir, a);
            after = ir.n_blocks ? ir.blocks[ir.n_blocks - 1].n_ops : 0;
            out->n_insns++;
            if (after > before)
                out->n_lowered++;
            taken++;
            va += in.size;
            if (ir.next_uniq > 440u)
                break;
        }
    }
}

// One axis as a 0..1 fraction. The guard lives in a function of its own, which is
// not only where it belongs: the optimiser proves the denominator positive here
// once instead of at five call sites, and the MSVC divide-by-zero warning stops
// firing on code it cannot prove but a reader can.
static double ratio(size_t num, size_t den) {
    return den > 0 ? (double)num / (double)den : 0.0;
}

double re_score_composite(const re_score_t *s) {
    double sum = 0.0;
    int axes = 0;
    if (s->n_pdata) {
        sum += ratio(s->n_pdata_hit, s->n_pdata);
        axes++;
    }
    if (s->n_edges) {
        sum += ratio(s->n_edges_ok, s->n_edges);
        axes++;
    }
    if (s->n_calls) {
        sum += ratio(s->n_calls_named, s->n_calls);
        axes++;
    }
    if (s->n_insns) {
        sum += ratio(s->n_lowered, s->n_insns);
        axes++;
    }
    if (s->n_indirect) {
        sum += ratio(s->n_indirect_ok, s->n_indirect);
        axes++;
    }
    return axes ? 100.0 * sum / (double)axes : 0.0;
}

void re_score_run(const re_pe_t *pe, re_code_t *code, const re_fscan_t *scan,
                  const re_xrefset_t *xs, const re_vec_t *jtables, const re_names_stat_t *names,
                  re_arena_t *a, re_score_t *out) {
    if (out)
        memset(out, 0, sizeof(*out));
    if (!pe || !code || !scan || !xs || !out)
        return;
    out->n_funcs = RE_VEC_LEN(&scan->funcs);
    out->n_pdata = RE_VEC_LEN(&pe->unwind);
    out->n_pdata_hit = pdata_hits(pe, scan);
    edge_sample(code, scan, jtables, a, out);
    call_stats(xs, scan, out);
    lower_sample(code, scan, a, out);
    // Each recovered jump table is one indirect dispatch that stopped being
    // unresolved, and each devirtualised call is one indirect transfer that
    // stopped being unknown, so the three together are the recovery axis:
    // resolved over every indirect transfer the image had.
    out->n_indirect = xs->n_indirect + RE_VEC_LEN(jtables);
    out->n_indirect_ok = RE_VEC_LEN(jtables);
    if (names && RE_VEC_LEN(&names->vcalls)) {
        out->n_indirect += RE_VEC_LEN(&names->vcalls);
        out->n_indirect_ok += RE_VEC_LEN(&names->vcalls);
    }
    out->score = re_score_composite(out);
}
