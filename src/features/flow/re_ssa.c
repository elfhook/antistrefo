// re_ssa.c - def use chains and dominators over one function.
// Module: feature (C11).
// Owns: the packed key, the def collection and the dominator tree.
// Depends: re_flow.h, re_ir, re_cfg. Pure graph and stream work: nothing here
//           reads bytes, so it is testable without an image.
#include "features/flow/re_flow.h"

#include "utils/algo/re_sort.h"

// keyid packs a varnode identity into one 64 bit key. The space in the high
// bits and the offset in the low ones, so sorting by keyid groups every
// definition of one location together in stream order, which is the shape a
// def-use query wants and the reason nothing here needs a hash table.
static uint64_t keyid_of(const re_varnode_t *vn) {
    return ((uint64_t)(uint32_t)vn->space << 32) | (uint32_t)vn->offset;
}

// Order by key, then by stream position, so the defs of one location form a
// chain in the order the instructions wrote them.
static int cmp_def(const void *pa, const void *pb, void *ctx) {
    const re_flow_def_t *a = (const re_flow_def_t *)pa;
    const re_flow_def_t *b = (const re_flow_def_t *)pb;
    (void)ctx;
    if (a->keyid != b->keyid)
        return a->keyid < b->keyid ? -1 : 1;
    if (a->seq != b->seq)
        return a->seq < b->seq ? -1 : 1;
    return 0;
}

// A definition is recorded for every op whose out varnode names stored state.
// A store into a stack slot is not one of these: the store's value rides in
// in[1] and the address in in[2], so the slot itself is not an out, and the
// pass would otherwise treat a write to memory as a foldable definition.
static bool def_writes(const re_varnode_t *vn) {
    switch (vn->space) {
        case RE_SPACE_REG:
        case RE_SPACE_UNIQUE:
        case RE_SPACE_CONST:
            return true;
        default:
            return false;
    }
}

// The block an instruction address belongs to, by binary search over the
// graph's ascending block starts. The CFG is the caller's authority on block
// boundaries, and an address below the first block belongs to no block.
static uint32_t block_of_addr(const re_cfg_t *g, uint64_t addr) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&g->blocks);
    if (!hi || addr < RE_VEC_AT(&g->blocks, re_cfg_block_t, 0).va)
        return 0;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (RE_VEC_AT(&g->blocks, re_cfg_block_t, mid).va <= addr)
            lo = mid;
        else
            hi = mid;
    }
    return (uint32_t)lo;
}

void re_flow_ssa_build(const re_ir_func_t *f, const re_cfg_t *g, re_arena_t *a,
                       re_flow_ssa_t *out) {
    uint32_t seq = 0;
    if (!out)
        return;
    re_vec_init(&out->defs, sizeof(re_flow_def_t));
    if (!f || !a)
        return;
    for (size_t bi = 0; bi < f->n_blocks; bi++) {
        const re_ir_block_t *blk = &f->blocks[bi];
        for (size_t k = 0; k < blk->n_ops; k++) {
            const re_ir_op_t *op = &blk->ops[k];
            re_flow_def_t d;
            if (!def_writes(&op->out))
                continue;
            d.addr = op->addr;
            d.keyid = keyid_of(&op->out);
            d.block = g ? block_of_addr(g, op->addr) : 0;
            d.op = (uint32_t)k;
            d.seq = seq++;
            d.size = op->out.size;
            d.space = op->out.space;
            d.key = op->out.offset;
            RE_VEC_PUSH(&out->defs, a, d);
        }
    }
    re_vec_sort(&out->defs, cmp_def, NULL);
}

// The chain for d's key starts at the first entry the binary search landed on.
// The previous definition is the last one before d in stream order, which is
// one step along the chain the caller can follow repeatedly to the top.
const re_flow_def_t *re_flow_ssa_def_before(const re_flow_ssa_t *s, const re_flow_def_t *d) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&s->defs);
    const re_flow_def_t *prev = NULL;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (RE_VEC_AT(&s->defs, re_flow_def_t, mid).keyid < d->keyid)
            lo = mid + 1;
        else
            hi = mid;
    }
    // The search converged lo onto hi, so the chain walk needs the vector end
    // as its bound: the group runs from the insertion point to the first entry
    // with a different key, and stopping at hi would walk nothing at all.
    for (size_t i = lo; i < RE_VEC_LEN(&s->defs); i++) {
        const re_flow_def_t *e = RE_VEC_PTR(&s->defs, re_flow_def_t, i);
        if (e->keyid != d->keyid || e->seq >= d->seq)
            break;
        prev = e;
    }
    return prev;
}

// The intersection walks whichever finger sits deeper in the spanning tree up
// toward the root. The root carries the highest number in this ordering, so
// the finger with the smaller number is the one that moves.
static uint32_t idom_intersect(const uint32_t *idom, const uint32_t *rpo, uint32_t a, uint32_t b) {
    while (a != b) {
        while (rpo[a] < rpo[b])
            a = idom[a];
        while (rpo[b] < rpo[a])
            b = idom[b];
    }
    return a;
}

// A depth first pass over the edges, recording the order blocks are first
// reached. The entry is block zero by construction, and a block no edge
// reaches is left out, which is how unreachable code stays out of the tree.
static uint32_t rpo_order(const re_cfg_t *g, uint32_t n, uint8_t *seen, uint32_t *order) {
    uint32_t stack[RE_CFG_MAX_BLOCKS];
    uint32_t sp = 0;
    uint32_t count = 0;
    stack[sp++] = 0;
    seen[0] = 1;
    while (sp) {
        uint32_t b = stack[--sp];
        order[count++] = b;
        for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
            const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
            if (e->from != b || e->to < 0 || e->to >= (int32_t)n || seen[e->to])
                continue;
            seen[e->to] = 1;
            stack[sp++] = (uint32_t)e->to;
        }
    }
    return count;
}

// One fixpoint sweep. A block's immediate dominator is the intersection of
// every processed predecessor's; the sweep repeats until nothing moved, which
// converges in a few passes on the small graphs one function produces.
static bool dom_sweep(const re_cfg_t *g, uint32_t n, const uint32_t *rpo, const uint32_t *order,
                      uint32_t count, uint32_t *idom) {
    bool changed = false;
    for (uint32_t oi = 1; oi < count; oi++) {
        uint32_t b = order[oi];
        uint32_t cand = RE_FLOW_IDOM_NONE;
        for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
            const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
            if (e->to != (int32_t)b || e->from >= n)
                continue;
            if (idom[e->from] == RE_FLOW_IDOM_NONE)
                continue;
            cand = cand == RE_FLOW_IDOM_NONE ? e->from : idom_intersect(idom, rpo, cand, e->from);
        }
        if (cand != RE_FLOW_IDOM_NONE && cand != idom[b]) {
            idom[b] = cand;
            changed = true;
        }
    }
    return changed;
}

void re_flow_dominators(const re_cfg_t *g, re_arena_t *a, uint32_t *idom) {
    uint32_t n = (uint32_t)RE_VEC_LEN(&g->blocks);
    uint32_t *rpo;
    uint8_t *seen;
    uint32_t *order;
    uint32_t count;
    if (!g || !idom || n == 0 || !a)
        return;
    for (uint32_t i = 0; i < n; i++)
        idom[i] = RE_FLOW_IDOM_NONE;
    rpo = (uint32_t *)re_arena_calloc(a, n, sizeof(uint32_t));
    seen = (uint8_t *)re_arena_calloc(a, n, 1);
    order = (uint32_t *)re_arena_calloc(a, n, sizeof(uint32_t));
    if (!rpo || !seen || !order)
        return;
    count = rpo_order(g, n, seen, order);
    // The root dominates itself, and the number the walk assigned it is the
    // highest, so every walk up the tree terminates at the entry.
    if (!count)
        return;
    idom[0] = 0;
    for (uint32_t i = 0; i < count; i++)
        rpo[order[i]] = count - i;
    while (dom_sweep(g, n, rpo, order, count, idom)) {
    }
}

// True when a dominates b: a is b, or sits on b's chain of immediate
// dominators. The entry ends every chain, so the walk always terminates.
bool re_flow_dominates(const uint32_t *idom, uint32_t n, uint32_t a, uint32_t b) {
    if (a >= n || b >= n)
        return false;
    while (b != RE_FLOW_IDOM_NONE) {
        if (b == a)
            return true;
        if (b == 0)
            break;
        b = idom[b];
    }
    return false;
}
