// re_func.c - the recursive descent that turns decoded control flow into functions.
// Module: feature (C11).
// Owns: seeding, the block walk, edge recording, and the stack frame size.
// Depends: re_func.h and re_code. A function is reported only if it was walked.
#include "features/code/re_func.h"

#include "features/pe/re_pe.h"

void re_fscan_init(re_fscan_t *s) {
    re_vec_init(&s->funcs, sizeof(re_func_t));
    re_vec_init(&s->edges, sizeof(re_edge_t));
}

typedef struct {
    re_code_t *code;
    re_arena_t *a;
    re_vec_t *edges; // re_edge_t
    re_vec_t *queue; // uint64_t, candidate function starts still to walk
    re_vec_t *out;   // re_func_t
} walk_t;

static void push_u64(re_arena_t *a, re_vec_t *v, uint64_t x) {
    RE_VEC_PUSH(v, a, x);
}

static void add_edge(re_arena_t *a, re_vec_t *v, uint64_t from, uint64_t to, uint8_t kind,
                     bool has_to) {
    re_edge_t e;
    e.from = from;
    e.to = to;
    e.kind = kind;
    e.has_to = has_to;
    RE_VEC_PUSH(v, a, e);
}

// A cheap byte test for a function start, used only by the sweep that looks for
// functions nothing points at. It never calls the decoder, because that sweep
// probes every byte of the section and a decode per byte would be hopeless.
static bool looks_like_start(const re_code_t *c, uint64_t va) {
    re_span_t b;
    const uint8_t *p;
    if (!re_code_at(c, va, &b) || b.n < 4)
        return false;
    p = (const uint8_t *)b.p;
    if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && (p[3] == 0xFA || p[3] == 0xFB))
        return true; // endbr64 or endbr32
    if (p[0] == 0x55)
        return true; // push rbp
    if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xE5)
        return true; // mov rbp, rsp
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC)
        return true; // sub rsp, imm8
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC)
        return true; // sub rsp, imm32
    return false;
}

// The stack a function reserves. Only a sub rsp inside the prologue window
// counts, and the window is counted in instructions this function actually walked
// rather than in bytes, so a frame size can never be read out of the next
// function when this one is short.
static bool sub_rsp(const re_insn_t *in, uint32_t *out) {
    if (in->insn_id != 0x0081 && in->insn_id != 0x0083)
        return false;
    if (in->modrm != 0xEC)
        return false;
    if (in->imm <= 0 || in->imm >= 65536)
        return false;
    *out = (uint32_t)in->imm;
    return true;
}
// A data reference is a RIP relative operand, or a wide immediate that looks like
// an address in this image. Both are how code reaches strings, jump tables and
// import addresses, and neither is a control flow edge, so they are recorded
// separately or a caller asking "what does this function touch" sees nothing.
static bool data_ref(const re_code_t *c, const re_insn_t *in) {
    if (in->is_call || in->is_branch)
        return false; // the operand is the transfer's own target, not a data use
    if (in->has_mem)
        return true;
    if (in->opsize == 8 && in->imm > 0xFFFF && (uint64_t)in->imm >= c->base)
        return true;
    return false;
}

// One direct transfer, and what to do about it. The distinction that matters is
// conditional against unconditional: a conditional branch target is another block
// of this same function, while an unconditional jmp is a tail call into a
// different function and its target must go to the function queue instead.
// Treating the second as a block is how one function ends up reporting another
// function's instructions as its own.
//
// A transfer through a RIP relative operand names its target too. That form is how
// a driver calls a Windows API, through the import slot, and calling it indirect
// would throw away the single most useful fact about the reference.
static void take_edge(walk_t *w, re_vec_t *blocks, const re_insn_t *in, re_func_t *f) {
    uint8_t kind = RE_EDGE_NONE;
    uint64_t target = in->has_target ? in->target : (in->has_mem ? in->mem : 0);
    bool have = in->has_target || in->has_mem;
    if (data_ref(w->code, in))
        add_edge(w->a, w->edges, in->addr, in->has_mem ? in->mem : (uint64_t)in->imm, RE_EDGE_DATA,
                 true);
    if (in->is_call)
        kind = RE_EDGE_CALL;
    else if (in->is_branch)
        kind = in->is_conditional ? RE_EDGE_COND : RE_EDGE_JUMP;
    if (kind == RE_EDGE_NONE)
        return;
    if (!have) {
        // An unresolved transfer is still a fact about the function: a call
        // through a register cannot be resolved, and an indirect jump is a
        // dispatch. Both are recorded so the report can say so out loud.
        add_edge(w->a, w->edges, in->addr, 0, kind, false);
        if (in->is_call)
            f->n_calls++;
        else {
            f->n_jumps++;
            f->flags |= RE_FUNC_JTABLE;
            if (!f->dispatch)
                f->dispatch = in->addr;
        }
        return;
    }
    add_edge(w->a, w->edges, in->addr, target, kind, true);
    if (in->is_call)
        f->n_calls++;
    else
        f->n_jumps++;
    if (!re_code_in_code(w->code, target)) {
        // A call through an import slot lands in data, not code, and that is
        // expected rather than a call that left the image.
        if (!in->has_mem)
            f->flags |= RE_FUNC_EXTERNAL;
        return;
    }
    if (in->is_call || !in->is_conditional)
        push_u64(w->a, w->queue, target);
    else if (!re_code_covered(w->code, target, 1))
        push_u64(w->a, blocks, target);
}

// Walk one function. Blocks are appended to a list and consumed with a cursor
// rather than popped, because the vector has no remove and a cursor needs none.
// Every instruction that can fall through queues the next address, which is what
// turns this into a walk rather than a single decode.
static void walk_func(walk_t *w, uint64_t start, re_func_t *f) {
    re_vec_t blocks;
    size_t cursor = 0;
    uint64_t hi = start;
    re_vec_init(&blocks, sizeof(uint64_t));
    push_u64(w->a, &blocks, start);
    f->va = start;
    f->dispatch = 0;
    f->rva = (uint32_t)(start - w->code->base);
    f->n_insns = 0;
    f->n_calls = 0;
    f->n_jumps = 0;
    f->flags = 0;
    f->name = re_str("");
    f->frame_size = 0;
    while (cursor < RE_VEC_LEN(&blocks) && f->n_insns < RE_FUNC_MAX_INSNS) {
        uint64_t va = *(const uint64_t *)RE_VEC_PTR(&blocks, uint64_t, cursor);
        re_insn_t in;
        uint32_t frame = 0;
        cursor++;
        if (!re_code_insn(w->code, va, &in))
            continue;
        if (re_code_covered(w->code, va, in.size))
            continue;
        re_code_mark(w->code, va, in.size);
        f->n_insns++;
        if (va + in.size > hi)
            hi = va + in.size;
        if (f->n_insns <= 12 && f->frame_size == 0 && sub_rsp(&in, &frame))
            f->frame_size = frame;
        if (in.is_return)
            f->flags |= RE_FUNC_RET;
        take_edge(w, &blocks, &in, f);
        if (!in.is_return && !(in.is_branch && !in.is_conditional))
            push_u64(w->a, &blocks, va + in.size);
    }
    f->size = (uint32_t)(hi - start);
    // A body that is little more than a jump is a thunk: a jump through the
    // import table, or a tail call the compiler left in place.
    if (f->n_insns <= 2 && f->n_jumps >= 1)
        f->flags |= RE_FUNC_THUNK;
    re_vec_truncate(&blocks, 0);
}

static int cmp_va(const void *a, const void *b, void *ctx) {
    const re_func_t *x = (const re_func_t *)a;
    const re_func_t *y = (const re_func_t *)b;
    (void)ctx;
    if (x->va < y->va)
        return -1;
    return x->va > y->va ? 1 : 0;
}

// The unwind table is the compiler's own list of where its functions begin and end.
// Where it is present it beats any inference from bytes: it gives a function that no
// call points at, such as one reached only through SEH or a runtime callback, and it
// gives the exact end rather than the end the walk happened to reach. It is not
// complete, because a leaf function needing no frame has no entry, so this runs
// alongside the sweep rather than instead of it.
static void unwind_pass(walk_t *w) {
    const re_pe_t *pe = w->code->pe;
    for (size_t i = 0; i < RE_VEC_LEN(&pe->unwind); i++) {
        const re_pe_unwind_t *u = RE_VEC_PTR(&pe->unwind, re_pe_unwind_t, i);
        uint64_t start = w->code->base + u->begin;
        if (!re_code_in_code(w->code, start) || re_code_covered(w->code, start, 1))
            continue;
        re_func_t f;
        walk_func(w, start, &f);
        if (f.n_insns == 0)
            continue;
        f.flags |= RE_FUNC_UNWIND;
        // The compiler knows where the function stops even when the walk stopped
        // early, so the declared end wins over the walked one.
        if (u->end > u->begin && f.rva + f.size < u->end)
            f.size = u->end - u->begin;
        RE_VEC_PUSH(w->out, w->a, f);
    }
}

// The prologue sweep. Functions reached only through a vtable or a driver
// dispatch table are not pointed at by any call, so without this pass they are
// invisible. It is a byte test, not a decode, and it only starts a walk on
// unmarked bytes, so the cost is one comparison per byte of code.
static void sweep(walk_t *w) {
    uint64_t va = 0;
    uint64_t len = 0;
    for (uint16_t r = 0; re_code_range(w->code, r, &va, &len); r++) {
        uint64_t end = va + len;
        for (uint64_t at = va; at < end; at++) {
            re_func_t f;
            if (re_code_covered(w->code, at, 1))
                continue;
            // A byte test says "sub rsp, 0x28" looks like a prologue. Inside a
            // function the compiler already described, that is a stack adjustment
            // mid body, and starting one there is how one real function became two.
            re_pe_unwind_t u;
            if (re_pe_unwind_covering(w->code->pe, (uint32_t)(at - w->code->base), &u) &&
                w->code->base + u.begin != at)
                continue;
            if (!looks_like_start(w->code, at))
                continue;
            walk_func(w, at, &f);
            if (f.n_insns == 0)
                continue;
            f.flags |= RE_FUNC_PROLOGUE;
            RE_VEC_PUSH(w->out, w->a, f);
            at += f.size ? f.size - 1 : 0;
        }
    }
}

// A function that begins where the compiler put an unwind entry takes its end from
// there too, whichever pass happened to discover it first. Most of the table is
// already reached by a call, so without this the declared end is available but
// unused, and a function the walk stopped short of keeps the short size.
static void adopt_unwind(const re_pe_t *pe, re_vec_t *funcs) {
    for (size_t i = 0; i < RE_VEC_LEN(funcs); i++) {
        re_func_t *f = RE_VEC_PTR(funcs, re_func_t, i);
        re_pe_unwind_t u;
        if (!re_pe_unwind_covering(pe, f->rva, &u) || u.begin != f->rva)
            continue;
        f->flags |= RE_FUNC_UNWIND;
        if (u.end > u.begin)
            f->size = u.end - u.begin;
    }
}

void re_func_scan(re_code_t *c, re_arena_t *a, re_fscan_t *out) {
    re_vec_t queue;
    walk_t w;
    size_t cursor = 0;
    re_fscan_init(out);
    re_vec_init(&queue, sizeof(uint64_t));
    w.code = c;
    w.a = a;
    w.edges = &out->edges;
    w.queue = &queue;
    w.out = &out->funcs;
    if (c->pe->entry_rva)
        push_u64(a, &queue, c->base + c->pe->entry_rva);
    for (size_t i = 0; i < RE_VEC_LEN(&c->pe->exports); i++) {
        const re_pe_exp_t *e = RE_VEC_PTR(&c->pe->exports, re_pe_exp_t, i);
        if (e->rva)
            push_u64(a, &queue, c->base + e->rva);
    }
    while (cursor < RE_VEC_LEN(&queue)) {
        uint64_t start = *(const uint64_t *)RE_VEC_PTR(&queue, uint64_t, cursor);
        re_func_t f;
        cursor++;
        if (!re_code_in_code(c, start) || re_code_covered(c, start, 1))
            continue;
        walk_func(&w, start, &f);
        if (f.n_insns == 0)
            continue;
        if (c->pe->entry_rva && f.rva == c->pe->entry_rva)
            f.flags |= RE_FUNC_ENTRY;
        RE_VEC_PUSH(&out->funcs, a, f);
    }
    unwind_pass(&w);
    sweep(&w);
    adopt_unwind(c->pe, &out->funcs);
    re_vec_sort(&out->funcs, cmp_va, NULL);
}

const re_func_t *re_func_at(const re_fscan_t *s, size_t index) {
    if (index >= RE_VEC_LEN(&s->funcs))
        return NULL;
    return RE_VEC_PTR(&s->funcs, re_func_t, index);
}

long re_func_index_of(const re_fscan_t *s, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&s->funcs);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const re_func_t *f = RE_VEC_PTR(&s->funcs, re_func_t, mid);
        if (va < f->va) {
            hi = mid;
        } else if (va >= f->va + f->size) {
            lo = mid + 1;
        } else {
            return (long)mid;
        }
    }
    return -1;
}

// How many transfers leave this function. Scoped to the function's own address
// range, because an edge belongs to whichever function contains its source.
size_t re_func_edge_count(const re_fscan_t *s, const re_func_t *f) {
    size_t n = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&s->edges); i++) {
        const re_edge_t *e = RE_VEC_PTR(&s->edges, re_edge_t, i);
        if (e->from >= f->va && e->from < f->va + f->size)
            n++;
    }
    return n;
}
