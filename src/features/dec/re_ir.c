// re_ir.c - arena backed storage for a lowered function. No allocation of its own.
// Module: feature (C11).
// Owns: growth of the block list and of each block's op array, and the release.
// Depends: re_ir.h and re_arena. Every byte comes from the caller's arena.
#include "features/dec/re_ir.h"

#include <stddef.h>
#include <string.h>

#include "utils/mem/re_arena.h"

// Grow a buffer to at least need elements, doubling so the cost is amortized and
// never a per-op realloc. The old contents are copied, the arena keeps the rest.
static void *ir_grow(re_arena_t *a, void *buf, size_t *cap, size_t need, size_t esz) {
    if (need <= *cap)
        return buf;
    size_t next = *cap ? *cap : 8;
    while (next < need) {
        next *= 2;
    }
    void *np = re_arena_alloc(a, next * esz);
    if (!np)
        return NULL;
    if (buf && *cap)
        memcpy(np, buf, *cap * esz);
    *cap = next;
    return np;
}

void re_ir_func_init(re_ir_func_t *f) {
    f->entry = 0;
    f->end = 0;
    f->blocks = NULL;
    f->n_blocks = 0;
    f->cap_blocks = 0;
    f->next_uniq = 0;
    f->params = NULL;
    f->n_params = 0;
    f->rets = NULL;
    f->n_rets = 0;
    f->frame_size = 0;
}

void re_ir_block_end(re_ir_func_t *f) {
    if (f->n_blocks)
        f->blocks[f->n_blocks - 1].size = f->end - f->blocks[f->n_blocks - 1].start;
}

re_ir_block_t *re_ir_block_begin(re_ir_func_t *f, re_arena_t *a, uint64_t start, uint64_t size) {
    f->blocks = (re_ir_block_t *)ir_grow(a, f->blocks, &f->cap_blocks, f->n_blocks + 1,
                                         sizeof(re_ir_block_t));
    if (!f->blocks)
        return NULL;
    re_ir_block_t *b = &f->blocks[f->n_blocks++];
    b->start = start;
    b->size = size;
    b->ops = NULL;
    b->n_ops = 0;
    b->cap_ops = 0;
    return b;
}

re_ir_op_t *re_ir_emit(re_ir_func_t *f, re_arena_t *a, re_ir_op_t op) {
    if (!f->n_blocks)
        return NULL;
    re_ir_block_t *b = &f->blocks[f->n_blocks - 1];
    b->ops = (re_ir_op_t *)ir_grow(a, b->ops, &b->cap_ops, b->n_ops + 1, sizeof(re_ir_op_t));
    if (!b->ops)
        return NULL;
    b->ops[b->n_ops] = op;
    return &b->ops[b->n_ops++];
}

re_varnode_t re_ir_vn(uint8_t space, uint16_t size, uint16_t offset) {
    re_varnode_t v;
    v.space = space;
    v.size = size;
    v.offset = offset;
    return v;
}

re_ir_op_t re_ir_mkop(re_ir_op_t op) {
    unsigned i;
    for (i = 0; i < 4; i++)
        op.in[i] = re_ir_vn(RE_SPACE_UNIQUE, 0, 0);
    op.const_val = 0;
    op.extra = 0;
    return op;
}

void re_ir_release(re_arena_t *a, re_ir_func_t *f) {
    (void)a;
    re_ir_func_init(f);
}
