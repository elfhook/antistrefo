// re_flow.c - the driver that composes the flow passes over one function.
// Module: feature (C11).
// Owns: the pass composition and the jump table binding into the graph.
// Depends: re_flow.h, re_cfg, re_jtable, re_code. The composition order is
//           the deobfuscation idioms first, then the value tracking, because
//           a recovered call target and a decoded string are facts the
//           tracking pass should see, and never the other way round.
#include "features/flow/re_flow.h"

#include "features/code/re_jtable.h"

#include <string.h>

void re_flow_stat_init(re_flow_stat_t *st, re_arena_t *a) {
    if (!st)
        return;
    memset(st, 0, sizeof(*st));
    re_vec_init(&st->strs, sizeof(re_flow_str_t));
    st->strs_a = a;
}

// The jump table whose dispatch sits inside this block, or NULL. The scan
// recorded the exact branch address, and the block is the whole instruction,
// so a containment test is the lookup: one block ends in one terminator.
static const re_jtable_t *table_for(const re_vec_t *jtables, const re_cfg_block_t *b,
                                    uint64_t base) {
    for (size_t i = 0; i < RE_VEC_LEN(jtables); i++) {
        const re_jtable_t *t = RE_VEC_PTR(jtables, re_jtable_t, i);
        if (t->at >= b->va && t->at < b->va + b->size && t->at >= base)
            return t;
    }
    return NULL;
}

// The block a resolved case starts in, by binary search over the ascending
// starts, or -1 when the case lands outside this function's blocks.
static long block_of(const re_cfg_t *g, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&g->blocks);
    if (!hi || va < RE_VEC_AT(&g->blocks, re_cfg_block_t, 0).va)
        return -1;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (RE_VEC_AT(&g->blocks, re_cfg_block_t, mid).va <= va)
            lo = mid;
        else
            hi = mid;
    }
    return (long)lo;
}

// Bind one indirect dispatch to its table. The block becomes a plain jump to
// the table's first case: the graph now has the switch's edges, the report
// counts the dispatch as resolved, and a reader sees a jump instead of a dead
// end. The remaining cases are the table's, not the graph's, because the
// dispatch's index register is runtime data and the graph says what it can
// prove.
static bool bind(re_cfg_t *g, const re_code_t *c, const re_vec_t *jtables, re_arena_t *a,
                 size_t bi) {
    re_cfg_block_t *b = RE_VEC_PTR(&g->blocks, re_cfg_block_t, bi);
    const re_jtable_t *t = table_for(jtables, b, c->base);
    uint64_t first;
    re_cfg_edge_t e;
    long to;
    if (!t)
        return false;
    first = re_jtable_target(c, t, 0);
    if (!first)
        return false;
    b->term = RE_CFG_TERM_JUMP;
    b->has_target = true;
    b->target = first;
    b->external = !re_code_in_code(c, first);
    e.from = (uint32_t)bi;
    to = block_of(g, first);
    e.to = (int32_t)to;
    e.kind = to >= 0 ? RE_CFG_EDGE_TAKEN : RE_CFG_EDGE_TAIL;
    // A tail edge is a resolved outcome, control demonstrably left the
    // function, so it is not counted as an unresolved destination.
    RE_VEC_PUSH(&g->edges, a, e);
    return true;
}

size_t re_flow_cfg_jtables(re_cfg_t *g, const re_code_t *c, const re_vec_t *jtables,
                           re_arena_t *a) {
    size_t bound = 0;
    if (!g || !c || !jtables || !a)
        return 0;
    for (size_t i = 0; i < RE_VEC_LEN(&g->blocks); i++) {
        re_cfg_block_t *b = RE_VEC_PTR(&g->blocks, re_cfg_block_t, i);
        if (b->term == RE_CFG_TERM_INDIRECT && bind(g, c, jtables, a, i))
            bound++;
    }
    return bound;
}

size_t re_flow_apply(re_ir_func_t *f, re_code_t *code, re_arena_t *a, re_flow_stat_t *st) {
    re_flow_stat_t local;
    re_flow_stat_t *s = st ? st : &local;
    if (!st)
        re_flow_stat_init(&local, a);
    if (!f)
        return 0;
    re_flow_deobf(f, code, a, s);
    re_flow_constprop(f, a, s);
    s->n_total = s->n_const + s->n_pred + s->n_callind + s->n_thunk + s->n_stackstr + s->n_jtable +
                 s->n_copy + s->n_dead;
    return s->n_total;
}
