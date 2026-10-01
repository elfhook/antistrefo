// re_cfg.c - partitions one function into basic blocks and links them.
// Module: feature (C11).
// Owns: block partitioning, terminator classification, and the edge list.
// Depends: re_cfg, re_dc_walk, re_code, re_func, re_vec.
#include "features/dec/re_cfg.h"

#include "features/dec/re_dc_walk.h"

const char *re_cfg_term_name(uint8_t term) {
    static const char *const kNames[] = {"fall",     "call", "cond",    "jump", "ret",
                                         "indirect", "cut",  "unknown", NULL};
    return term < 8 ? kNames[term] : "unknown";
}

const char *re_cfg_edge_name(uint8_t kind) {
    static const char *const kNames[] = {"fall", "taken", "tail"};
    return kind < 3 ? kNames[kind] : "fall";
}

// Index of the block starting at or below va, or -1 when va precedes the entry.
// A branch into the middle of a block is reported against the block that contains
// it rather than dropped, because an edge that exists but resolves to the wrong
// block is still a real edge and hiding it would lose a path.
static long block_of(const uint64_t *starts, size_t nb, uint64_t va) {
    if (!nb || va < starts[0])
        return -1;
    size_t lo = 0;
    size_t hi = nb - 1;
    while (lo < hi) {
        size_t mid = lo + (hi - lo + 1) / 2;
        if (starts[mid] <= va)
            lo = mid;
        else
            hi = mid - 1;
    }
    return (long)lo;
}

// Collect the block starts: the entry, then every address the decompiler gave a
// label to. Labels are already ascending and the entry is the lowest address in
// the function, so the list is built in order and needs no sort.
static size_t collect_starts(const re_dc_walk_t *w, const re_func_t *f, uint64_t *starts,
                             bool *truncated) {
    size_t n = RE_VEC_LEN(&w->insns);
    size_t nb = 0;
    *truncated = false;
    starts[nb++] = f->va;
    for (size_t i = 0; i < n; i++) {
        const re_insn_t *in = RE_VEC_PTR(&w->insns, re_insn_t, i);
        if (!re_dc_label_of(w, in->addr) || in->addr == f->va)
            continue;
        if (in->addr <= starts[nb - 1])
            continue;
        if (nb >= RE_CFG_MAX_BLOCKS) {
            *truncated = true;
            break;
        }
        starts[nb++] = in->addr;
    }
    return nb;
}

// How a block stops, read off the last instruction of it. is_return is checked
// before is_branch because a ret is not a branch, and a call before both because
// a call ends a block in the walk even though control returns to the next one.
static uint8_t classify(const re_insn_t *last, bool *has_target, uint64_t *target) {
    *has_target = false;
    *target = 0;
    if (!last)
        return RE_CFG_TERM_UNKNOWN;
    if (last->is_return)
        return RE_CFG_TERM_RET;
    if (last->is_call)
        return RE_CFG_TERM_CALL;
    if (last->is_branch) {
        if (!last->is_conditional && !last->has_target)
            return RE_CFG_TERM_INDIRECT;
        if (last->is_conditional && !last->has_target)
            return RE_CFG_TERM_UNKNOWN;
        *has_target = true;
        *target = last->target;
        return last->is_conditional ? RE_CFG_TERM_COND : RE_CFG_TERM_JUMP;
    }
    // The walk stops for three reasons besides a terminator: the next bytes were
    // already claimed by another block, the decode failed, or the function extent
    // ran out. None of those is a fallthrough, so it is reported as a cut rather
    // than dressed up as one.
    return RE_CFG_TERM_CUT;
}

static void add_edge(re_cfg_t *o, re_arena_t *a, uint32_t from, int32_t to, uint8_t kind) {
    re_cfg_edge_t e;
    e.from = from;
    e.to = to;
    e.kind = kind;
    // A tail call has no destination by definition, so it is not an unresolved
    // edge. Counting it as one would report a known outcome as a failure.
    if (to < 0 && kind != RE_CFG_EDGE_TAIL)
        o->n_unresolved++;
    RE_VEC_PUSH(&o->edges, a, e);
}

// The successors of each block. A conditional branch has two, everything else has
// at most one, and a jump whose target leaves the function is a tail call rather
// than an edge to a block that does not exist.
static void link_edges(re_cfg_t *o, const uint64_t *starts, size_t nb, const re_func_t *f,
                       re_arena_t *a) {
    for (size_t i = 0; i < nb; i++) {
        const re_cfg_block_t *b = RE_VEC_PTR(&o->blocks, re_cfg_block_t, i);
        bool outside = false;
        if (b->term == RE_CFG_TERM_COND) {
            long t = block_of(starts, nb, b->target);
            add_edge(o, a, (uint32_t)i, (int32_t)t, RE_CFG_EDGE_TAKEN);
            if (i + 1 < nb)
                add_edge(o, a, (uint32_t)i, (int32_t)(i + 1), RE_CFG_EDGE_FALL);
            continue;
        }
        if (b->term == RE_CFG_TERM_JUMP) {
            long t = block_of(starts, nb, b->target);
            outside = b->target < f->va || b->target >= f->va + f->size;
            add_edge(o, a, (uint32_t)i, outside ? -1 : (int32_t)t,
                     outside ? RE_CFG_EDGE_TAIL : RE_CFG_EDGE_TAKEN);
            continue;
        }
        // Nothing else falls through. A ret leaves the function, a call returns to
        // the instruction after it, and a block the walk cut short or ended on an
        // indirect branch has no successor we can claim. The next block being
        // adjacent is not evidence that control reaches it, so no edge is invented.
    }
}

bool re_cfg_build(re_code_t *c, const re_func_t *f, re_cfg_t *out, re_arena_t *a) {
    re_dc_walk_t w = {0};
    uint64_t starts[RE_CFG_MAX_BLOCKS];
    bool truncated = false;
    re_vec_init(&out->blocks, sizeof(re_cfg_block_t));
    re_vec_init(&out->edges, sizeof(re_cfg_edge_t));
    out->n_unknown = 0;
    out->n_unresolved = 0;
    out->truncated = false;
    if (!c || !f || !out || !a)
        return false;
    re_dc_walk(c, f, &w, a);
    size_t n = RE_VEC_LEN(&w.insns);
    if (!n)
        return false;
    size_t nb = collect_starts(&w, f, starts, &truncated);
    out->truncated = truncated;
    for (size_t i = 0; i < nb; i++) {
        re_cfg_block_t b;
        const re_insn_t *first = RE_VEC_PTR(&w.insns, re_insn_t, 0);
        const re_insn_t *last = first;
        uint32_t count = 0;
        for (size_t k = 0; k < n; k++) {
            const re_insn_t *in = RE_VEC_PTR(&w.insns, re_insn_t, k);
            if (in->addr < starts[i])
                continue;
            if (i + 1 < nb && in->addr >= starts[i + 1])
                break;
            if (in->addr == starts[i])
                first = in;
            last = in;
            count++;
        }
        if (!count)
            continue;
        b.va = starts[i];
        b.size = (uint32_t)(last->addr + last->size - starts[i]);
        b.n_insns = count;
        b.term = classify(last, &b.has_target, &b.target);
        b.external = b.has_target && (b.target < f->va || b.target >= f->va + f->size);
        if (b.term == RE_CFG_TERM_UNKNOWN || b.term == RE_CFG_TERM_CUT)
            out->n_unknown++;
        RE_VEC_PUSH(&out->blocks, a, b);
    }
    if (!RE_VEC_LEN(&out->blocks))
        return false;
    nb = RE_VEC_LEN(&out->blocks);
    for (size_t i = 0; i < nb; i++) {
        const re_cfg_block_t *b = RE_VEC_PTR(&out->blocks, re_cfg_block_t, i);
        if (b->va != starts[i])
            starts[i] = b->va;
    }
    link_edges(out, starts, nb, f, a);
    return true;
}
