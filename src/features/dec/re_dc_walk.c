// re_dc_walk.c - decodes a function body into an address ordered list.
// Module: feature (C11).
// Owns: the traversal, so each block is decoded once and labels cannot drift.
// Depends: re_dc_walk.h. The decoder is reached through code->dis, not directly.
// Depends: re_dc_walk.h. The decoder is reached through code->dis, never directly.
#include "features/dec/re_dc_walk.h"

#include "utils/mem/re_vec.h"

#include <stdlib.h>
#include <string.h>

// Does this instruction end the current block? A return ends it. A call does not:
// calls are transparent to control flow and the instruction after one is still the
// fallthrough of the same block. A jump of any kind does, because the next
// instruction is reached by falling through at most.
static bool block_end(const re_insn_t *in) {
    if (in->is_return)
        return true;
    if (in->is_call)
        return false;
    return in->is_branch;
}

static bool in_func(uint64_t va, uint64_t fva, uint64_t fend) {
    return va >= fva && va < fend;
}

// Decode one block from start, appending what it finds. A block that overlaps bytes
// already claimed by another block is abandoned at the first overlap, which keeps a
// mis decoded target from pulling the walk into the middle of an instruction.
static void walk_block(re_code_t *code, uint64_t start, uint64_t fva, uint64_t fend, uint8_t *seen,
                       re_dc_walk_t *w, re_arena_t *a) {
    uint64_t va = start;
    while (in_func(va, fva, fend)) {
        re_insn_t in;
        if (!re_code_insn(code, va, &in))
            return;
        if (in.size == 0 || va + in.size > fend)
            return;
        for (uint32_t i = 0; i < in.size; i++) {
            if (seen[va - fva + i])
                return;
        }
        for (uint32_t i = 0; i < in.size; i++)
            seen[va - fva + i] = 1;
        RE_VEC_PUSH(&w->insns, a, in);
        // Any branch that ends this block makes its target a block start. A
        // conditional one is obvious, but an unconditional jump is equally a new
        // block, and leaving its target unlabelled is what makes a thunk read as one
        // undifferentiated run of instructions instead of a jump to somewhere else.
        if (in.is_branch && in.has_target && in_func(in.target, fva, fend)) {
            re_dc_label_t l;
            l.va = in.target;
            l.label = 0;
            RE_VEC_PUSH(&w->labels, a, l);
        }
        va += in.size;
        // The instruction after a conditional branch is a block start in its own
        // right: it is where control goes when the branch is not taken. Without it
        // the fall-through path has no block of its own and lands on whatever block
        // happens to follow, which is the branch target rather than the fall path.
        if (in.is_conditional && in_func(va, fva, fend)) {
            re_dc_label_t fl;
            fl.va = va;
            fl.label = 0;
            RE_VEC_PUSH(&w->labels, a, fl);
        }
        if (block_end(&in))
            return;
    }
}

// Both vectors lead with an 8 byte address, so one comparator orders either. It
// reads through uint64_t rather than the struct, which keeps it valid for a struct
// whose first field is a uint64_t and whose rest may later grow.
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = 0, y = 0;
    memcpy(&x, a, sizeof(x));
    memcpy(&y, b, sizeof(y));
    return (x < y) ? -1 : (x > y);
}

static void dedupe_labels(re_dc_walk_t *w) {
    size_t n = RE_VEC_LEN(&w->labels);
    re_dc_label_t *v = RE_VEC_PTR(&w->labels, re_dc_label_t, 0);
    uint32_t next = 1;
    if (!n)
        return;
    qsort(v, n, sizeof(*v), cmp_u64);
    for (size_t i = 0; i < n; i++) {
        if (i && v[i].va == v[i - 1].va)
            continue;
        v[i].label = next++;
    }
    // Compact away the duplicates the pass above skipped, so the label lookup can
    // be a binary search over a list with no repeats.
    size_t out = 0;
    for (size_t i = 0; i < n; i++) {
        if (i && v[i].va == v[i - 1].va)
            continue;
        v[out++] = v[i];
    }
    w->labels.len = out;
}

// Is there an instruction at this address? Used to drop a label for a block the walk
// never managed to decode, which happens when the function's recorded extent stops
// short of a branch target. Such a label would be printed as a destination that is
// never defined, so it is better to have the emitter fall back to the address.
static bool has_insn_at(const re_dc_walk_t *w, uint64_t va) {
    size_t lo = 0, hi = RE_VEC_LEN(&w->insns);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t a = RE_VEC_AT(&w->insns, re_insn_t, mid).addr;
        if (a == va)
            return true;
        if (a < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return false;
}

// Drop labels with no instruction behind them, so a label in the output always has a
// body. Run after the instructions are sorted, because the check is a search.
static void prune_labels(re_dc_walk_t *w) {
    re_dc_label_t *v = RE_VEC_PTR(&w->labels, re_dc_label_t, 0);
    size_t n = RE_VEC_LEN(&w->labels);
    size_t out = 0;
    for (size_t i = 0; i < n; i++) {
        if (has_insn_at(w, v[i].va))
            v[out++] = v[i];
    }
    w->labels.len = out;
}

void re_dc_walk(re_code_t *code, const re_func_t *f, re_dc_walk_t *w, re_arena_t *a) {
    uint64_t fend = f->va + f->size;
    uint8_t *seen;
    // The vectors carry an element size, and a zeroed re_vec_t has none: every push
    // would allocate zero bytes and every read would alias element zero. Init here
    // rather than at each call site, so a caller cannot get this wrong.
    re_vec_init(&w->insns, sizeof(re_insn_t));
    re_vec_init(&w->labels, sizeof(re_dc_label_t));
    w->n_unknown = 0;
    seen = (uint8_t *)re_arena_calloc(a, f->size ? f->size : 1, 1);
    if (!seen)
        return;
    // The entry is a block start even when nothing branches to it, so it gets a
    // label too and the emitter never has to special case the first block.
    re_dc_label_t l;
    l.va = f->va;
    l.label = 0;
    RE_VEC_PUSH(&w->labels, a, l);
    walk_block(code, f->va, f->va, fend, seen, w, a);
    // Walk every block start the first block revealed, and then every block start
    // those revealed. walk_block stops at a terminator, so the entry block alone is
    // the whole function unless its targets are followed too. The list grows while
    // it is being read, which is the whole traversal: a block reached from two
    // predecessors is already marked in seen, so it is decoded once, and a loop
    // back to an earlier block adds nothing and so the walk terminates.
    for (size_t i = 0; i < RE_VEC_LEN(&w->labels); i++) {
        uint64_t sva = RE_VEC_AT(&w->labels, re_dc_label_t, i).va;
        if (sva < f->va || sva >= fend || seen[sva - f->va])
            continue;
        walk_block(code, sva, f->va, fend, seen, w, a);
    }
    dedupe_labels(w);
    if (RE_VEC_LEN(&w->insns) > 1) {
        re_insn_t *v = RE_VEC_PTR(&w->insns, re_insn_t, 0);
        qsort(v, RE_VEC_LEN(&w->insns), sizeof(*v), cmp_u64);
    }
    prune_labels(w);
}

uint32_t re_dc_label_of(const re_dc_walk_t *w, uint64_t va) {
    size_t lo = 0, hi = RE_VEC_LEN(&w->labels);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const re_dc_label_t *v = RE_VEC_PTR(&w->labels, re_dc_label_t, mid);
        if (v->va == va)
            return v->label;
        if (v->va < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}
