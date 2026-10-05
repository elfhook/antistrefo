// re_score.h - the quality scoreboard: analysis quality as numbers a gate demands.
// Module: feature (C11).
// Owns: the six analysis ratios, their composite, and the run that measures them.
// Depends: re_pe, re_code, re_func, re_xref, re_jtable, re_arena, re_vec. The
//           decoder is reached through the code map, never directly.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_jtable.h"
#include "features/code/re_xref.h"
#include "features/flow/re_names.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

// How many functions the per function measurements sample. A one hundred and fifty
// thousand function image cannot be walked end to end for a scoreboard without the
// scoreboard becoming the analysis, so the per function axes are sampled and the
// whole image axes are not. The sample is the first functions in scan order, which
// is stable for a given image, so two runs over one file agree.
#define RE_SCORE_SAMPLE 64u

// The instruction budget for the lowering coverage measure, across the sample. A
// bound here is what keeps a scoreboard run from decoding a whole image twice.
#define RE_SCORE_INSN_BUDGET 8192u

// One function may be measured at most this long, so one huge function cannot eat
// the whole budget and leave the rest of the sample unmeasured.
#define RE_SCORE_FUNC_INSNS 512u

// Every axis answers one question a decompiler depends on, and each is reported
// with its own denominator so a reader can see how much evidence stands behind the
// composite rather than trusting a single blended number.
typedef struct {
    size_t n_funcs;       // functions the walk recovered
    size_t n_pdata;       // RUNTIME_FUNCTION entries, 0 when the image has none
    size_t n_pdata_hit;   // functions starting exactly where the table says
    size_t n_edges;       // CFG edges over the sampled functions
    size_t n_edges_ok;    // edges landing on a known block or a declared exit
    size_t n_calls;       // call references the xref pass indexed
    size_t n_calls_named; // call targets carrying a name of any provenance
    size_t n_insns;       // instructions measured for lowering coverage
    size_t n_lowered;     // of those, ones the arch lowered to at least one op
    size_t n_indirect;    // unresolved transfers plus the tables and virtual
                          // calls that resolve some
    size_t n_indirect_ok; // of those, the dispatches and calls recovered
    double score;         // the composite, 0 to 100
} re_score_t;

// Measure every axis. The caller passes the whole analysed context, and the
// sampling happens inside, so no caller re-derives what a function sample is.
// names carries the devirtualisation record; its recovered calls land on the
// indirect axis, because a virtual call whose target was recovered stopped
// being indirect in exactly the sense a jtable-bound dispatch did.
void re_score_run(const re_pe_t *pe, re_code_t *code, const re_fscan_t *scan,
                  const re_xrefset_t *xs, const re_vec_t *jtables, const re_names_stat_t *names,
                  re_arena_t *a, re_score_t *out);

// The composite from an already filled record: the mean of the axes that have
// evidence, as a percentage. An axis with no denominator is skipped, not counted
// as zero, because an image without an exception table says nothing about how
// well functions were recovered.
double re_score_composite(const re_score_t *s);
#ifdef __cplusplus
}
#endif
