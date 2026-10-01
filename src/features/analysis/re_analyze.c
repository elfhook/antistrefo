// re_analyze.c - runs every pass over one file and records what each one did.
// Module: feature (C11).
// Owns: the pass order, the per pass timing, and the shared context's contents.
// Depends: re_analyze, re_pe, re_code, re_func, re_xref, re_jtable, re_strings,
//           re_regions, re_stack, re_flirt, re_clock.
#include "features/analysis/re_analyze.h"

#include "features/code/re_func.h"
#include "features/pe/re_format.h"
#include "utils/sys/re_err.h"
#include "utils/sys/re_time.h"

static const char *const kPassNames[RE_PASS_COUNT] = {
    "format", "functions", "xrefs", "jtables", "strings", "regions", "stack", "flirt",
};

// The record for one pass, created before it runs so that a pass which cannot run
// still has somewhere to say so. Recorded first and filled in after, because a pass
// that returns early has not run and its slot must say that rather than be absent.
static re_pass_stat_t *begin_pass(re_analysis_t *an, re_arena_t *a, re_pass_t pass) {
    re_pass_stat_t st;
    st.pass = pass;
    st.ms = 0;
    st.count = 0;
    st.ran = false;
    st.skip = RE_PASS_RAISED_NONE;
    st.partial = false;
    RE_VEC_PUSH(&an->passes, a, st);
    return RE_VEC_PTR(&an->passes, re_pass_stat_t, RE_VEC_LEN(&an->passes) - 1);
}

// Time one pass. The start is taken before the body and the end after, so a pass
// that is skipped costs only the call, which is what makes a zero mean "did no
// work" rather than "was not measured".
static uint64_t elapsed_since(uint64_t t0) {
    uint64_t t1 = re_clock_ms();
    return t1 >= t0 ? t1 - t0 : 0;
}

// Ran and found nothing is not the same as could not run. A clean driver with no jump
// tables in it is a real result, and reporting that as a skip would put a "nothing to
// analyse" next to a pass that did its job and correctly came back empty. So a pass
// that ran leaves count at whatever it found, including zero, and only a pass that
// bailed before it started records a skip.
static void finished(re_pass_stat_t *st) {
    st->ran = true;
}

static void run_format(re_analysis_t *an, re_pass_stat_t *st) {
    st->count = an->pe.n_sec;
    st->ran = true;
    if (!an->pe.valid)
        st->skip = RE_PASS_SKIP_UNSUPPORTED;
}

static void run_funcs(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    if (!an->has_pe) {
        st->skip = RE_PASS_SKIP_UNSUPPORTED;
        return;
    }
    if (!an->has_code) {
        st->skip = RE_PASS_SKIP_NO_DECODER;
        return;
    }
    re_func_scan(&an->code, a, &an->scan);
    st->count = RE_VEC_LEN(&an->scan.funcs);
    finished(st);
}

static void run_xrefs(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    if (!RE_VEC_LEN(&an->scan.funcs)) {
        st->skip = st->ran ? RE_PASS_SKIP_EMPTY : RE_PASS_SKIP_UNSUPPORTED;
        if (st->ran)
            return;
        st->skip = RE_PASS_SKIP_UNSUPPORTED;
        return;
    }
    re_xref_build(&an->code, &an->scan, &an->pe, a, &an->xs);
    st->count = RE_VEC_LEN(&an->xs.fwd);
    st->ran = true;
    if (an->xs.n_indirect)
        st->partial = true; // some transfers had no resolvable target
}

static void run_jtables(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    if (!an->has_code) {
        st->skip = RE_PASS_SKIP_NO_DECODER;
        return;
    }
    re_vec_init(&an->jtables, sizeof(re_jtable_t));
    re_jtable_scan(&an->code, &an->scan, a, &an->jtables);
    st->count = RE_VEC_LEN(&an->jtables);
    finished(st);
}

static void run_strings(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    re_strings_init(&an->strs);
    re_strings_scan(an->file.whole, 4, 20000, a, &an->strs);
    re_strings_devices(an->file.whole, 1024, a, &an->strs);
    re_strings_pdb(an->file.whole, a, &an->strs);
    st->count = RE_VEC_LEN(&an->strs.hits);
    finished(st);
}

static void run_regions(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    if (!an->has_pe) {
        st->skip = RE_PASS_SKIP_UNSUPPORTED;
        return;
    }
    bool truncated = false;
    re_vec_init(&an->regions, sizeof(re_region_t));
    re_region_scan(&an->code, &an->scan, &an->xs, &an->pe, 4096, &an->regions, &truncated, a);
    st->count = RE_VEC_LEN(&an->regions);
    st->partial = truncated;
    finished(st);
}

// The stack pass is the one that cannot be summarised by a single count, because its
// result is per function. It is measured over a bounded sample so the cost of a
// 150,000 function image is reported rather than incurred.
#define RE_STACK_SAMPLE 256u

static void run_stack(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    size_t n = RE_VEC_LEN(&an->scan.funcs);
    if (!n) {
        st->skip = RE_PASS_SKIP_EMPTY;
        return;
    }
    size_t take = n < RE_STACK_SAMPLE ? n : RE_STACK_SAMPLE;
    for (size_t i = 0; i < take; i++) {
        re_stack_t s;
        re_stack_analyze(&an->code, RE_VEC_PTR(&an->scan.funcs, re_func_t, i), a, &s);
    }
    st->count = take;
    st->ran = true;
    if (take < n)
        st->partial = true; // sampled, so the total image was not covered
}

static void run_flirt(re_analysis_t *an, re_arena_t *a, re_pass_stat_t *st) {
    re_vec_init(&an->sigs, sizeof(re_sig_t));
    st->count = re_flirt_builtin(a, &an->sigs);
    finished(st);
}

void re_analysis_init(re_analysis_t *an, re_arena_t *a) {
    memset(an, 0, sizeof(*an));
    an->arena = a;
    re_vec_init(&an->passes, sizeof(re_pass_stat_t));
    re_vec_init(&an->jtables, sizeof(re_jtable_t));
    re_vec_init(&an->regions, sizeof(re_region_t));
    re_vec_init(&an->sigs, sizeof(re_sig_t));
    re_strings_init(&an->strs);
}

// The pass table. Each entry says what it needs and what it produces, so the order is
// data rather than a chain of calls: a pass that cannot run records why and the next
// one still gets its turn.
static void run_pass(re_analysis_t *an, re_arena_t *a, re_pass_t pass) {
    re_pass_stat_t *st = begin_pass(an, a, pass);
    uint64_t t0 = re_clock_ms();
    switch (pass) {
        case RE_PASS_FORMAT:
            run_format(an, st);
            break;
        case RE_PASS_FUNCS:
            run_funcs(an, a, st);
            break;
        case RE_PASS_XREFS:
            run_xrefs(an, a, st);
            break;
        case RE_PASS_JTABLES:
            run_jtables(an, a, st);
            break;
        case RE_PASS_STRINGS:
            run_strings(an, a, st);
            break;
        case RE_PASS_REGIONS:
            run_regions(an, a, st);
            break;
        case RE_PASS_STACK:
            run_stack(an, a, st);
            break;
        case RE_PASS_FLIRT:
            run_flirt(an, a, st);
            break;
        default:
            st->skip = RE_PASS_SKIP_UNSUPPORTED;
            break;
    }
    st->ms = elapsed_since(t0);
}

bool re_analysis_open(re_analysis_t *an, re_arena_t *a, const char *path) {
    re_analysis_init(an, a);
    an->path = re_str(re_arena_strdup(a, path));
    if (re_file_open(path, a, &an->file) != RE_OK)
        return false;
    if (re_format_detect(an->file.whole) == RE_FMT_PE &&
        re_pe_parse(an->file.whole, a, &an->pe) == RE_OK)
        an->has_pe = an->pe.valid;
    if (an->has_pe) {
        const re_disasm_t *dis = re_disasm_find("x86-64");
        an->has_code = dis && re_code_init(&an->code, an->file.whole, &an->pe, dis, a);
    }
    for (int i = 0; i < RE_PASS_COUNT; i++)
        run_pass(an, a, (re_pass_t)i);
    an->ok = true;
    return true;
}

void re_analysis_close(re_analysis_t *an) {
    re_file_close(&an->file);
    an->ok = false;
}

const re_pass_stat_t *re_analysis_pass(const re_analysis_t *an, re_pass_t pass) {
    for (size_t i = 0; i < RE_VEC_LEN(&an->passes); i++) {
        const re_pass_stat_t *st = RE_VEC_PTR(&an->passes, re_pass_stat_t, i);
        if (st->pass == pass)
            return st;
    }
    return NULL;
}

const char *re_analysis_pass_name(re_pass_t pass) {
    return pass < RE_PASS_COUNT ? kPassNames[pass] : "unknown";
}

const char *re_analysis_skip_name(uint8_t skip) {
    switch (skip) {
        case RE_PASS_SKIP_UNSUPPORTED:
            return "not supported for this format";
        case RE_PASS_SKIP_EMPTY:
            return "nothing to analyse";
        case RE_PASS_SKIP_NO_DECODER:
            return "no instruction decoder in this build";
        case RE_PASS_SKIP_LIMIT:
            return "hit the result cap";
        default:
            return "";
    }
}

bool re_analysis_stack_of(re_analysis_t *an, size_t index, re_stack_t *out) {
    if (index >= RE_VEC_LEN(&an->scan.funcs) || !out)
        return false;
    re_stack_analyze(&an->code, RE_VEC_PTR(&an->scan.funcs, re_func_t, index), an->arena, out);
    return true;
}
