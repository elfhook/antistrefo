// re_rules.h - capability detection over static facts. The capa-lite layer.
// Module: feature (C11).
// Owns: the rule table, signal evaluation, and finding emission.
// Depends: re_pe, re_strings, re_json, re_hash. No I/O, no code body analysis.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_pe.h"
#include "features/re_strings.h"
#include "utils/re_json.h"

typedef enum {
    RE_SIG_IMPORT = 0,      // an imported symbol equals arg
    RE_SIG_STRING,          // some extracted string matches arg, case insensitive
    RE_SIG_BYTES,           // some extracted string contains arg, case insensitive
    RE_SIG_CONST,           // the little endian value of num appears in the image
    RE_SIG_DYN_RESOLVE,     // imports MmGetSystemRoutineAddress or GetProcAddress
    RE_SIG_SECTION_ENTROPY, // any section entropy above num, in bits per byte
    RE_SIG_DYNAMIC_DEVICE,  // a device name is built at runtime
    RE_SIG_NO_PDB,          // no debug directory, so provenance is unknown
    RE_SIG_OVERLAY,         // data after the last section that is not a signature
    RE_SIG_THIN_IMPORTS,    // fewer than num imported symbols yet many strings
    RE_SIG_KERNEL,          // the image is a native subsystem driver
} re_sig_kind_t;

typedef struct {
    re_sig_kind_t kind;
    const char *arg; // symbol, substring, or a pattern for RE_SIG_STRING
    uint64_t num;    // threshold, or the value for RE_SIG_CONST
} re_signal_t;

typedef struct {
    const char *id;
    const char *name;
    const char *why;
    int severity; // 0 informational, 3 high
    int score;    // triage points, roughly comparable to the API surface score
    const re_signal_t *sigs;
    size_t n_sigs;
    bool match_all; // true needs every signal, false needs any one
} re_rule_t;

typedef struct {
    const char *id;
    const char *name;
    int severity;
    int score;
    const char *evidence; // which signal fired, for the agent to check
} re_finding_t;

const re_rule_t *re_rule_table(size_t *count);
const re_rule_t *re_rule_find(const char *id);

// Evaluate every rule. Returns the number of findings written. out is a vec of
// re_finding_t, and the strings are arena owned by the caller.
size_t re_rules_eval(re_span_t img, const re_pe_t *pe, const re_strings_t *st, re_arena_t *a,
                     re_vec_t *out);

// Emit the findings array. Emits nothing when there are no findings beyond the
// informational tier, so a clean file produces a short response.
void re_rules_emit(re_jw_t *w, const re_vec_t *findings, bool include_info);
