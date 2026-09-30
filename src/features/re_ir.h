// re_ir.h - the register transfer IR vocabulary and its arena backed storage.
// Module: feature (C11).
// Owns: the IR types, the block and op storage for one function, and the release.
// Depends: re_buf and re_arena. Adding Capstone to the core is forbidden; see 8.1.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/re_buf.h"

// Where a varnode lives. Side effects are explicit in the IR, never implied by a
// register, which is what lets an emulator and a decompiler share one lowering.
typedef enum {
    RE_SPACE_CONST = 0, // literal, no storage
    RE_SPACE_REG,       // architectural register
    RE_SPACE_STACK,     // stack slot, offset relative to the frame
    RE_SPACE_HEAP,      // memory at an address in a register or constant
    RE_SPACE_UNIQUE,    // SSA style temporary
    RE_SPACE_IOP,       // an I/O register, never mapped to normal memory
} re_space_t;

typedef struct {
    uint16_t size;   // bytes, 1, 2, 4, 8 or 16
    uint16_t offset; // register index, stack offset, or nothing
    uint8_t space;
} re_varnode_t;

// The kind of an op, kept distinct from re_ir_op_t which is the op itself.
typedef enum {
    RE_OP_UNIMPL = 0, // an instruction the arch does not model yet
    RE_OP_CONST,      // out := const
    RE_OP_VAR,        // out := var
    RE_OP_LOAD,       // out := load(input)  the only read side effect
    RE_OP_STORE,      // store(input, input)  the only write side effect
    RE_OP_BRANCH,     // goto input
    RE_OP_CBRANCH,    // if input then goto input
    RE_OP_RETURN,     // return with optional inputs
    RE_OP_CALL,       // call with optional inputs
    RE_OP_CALLIND,    // indirect call
    RE_OP_INT,        // interrupt or trap
    RE_OP_MULTIEQUAL, // phi node at a control flow join
} re_op_kind_t;

typedef struct {
    re_op_kind_t op;
    re_varnode_t out; // unused when out.space is RE_SPACE_CONST
    re_varnode_t in[4];
    int64_t const_val; // meaningful only for RE_OP_CONST
    uint32_t extra;    // space for arch specific payloads
} re_ir_op_t;

// A block of lowered ops for one basic block. Ops are a flat array, no tree, so
// the emitter can walk them in address order without allocating.
typedef struct {
    uint64_t start; // virtual address of the first op
    uint64_t size;  // bytes consumed from the original image
    re_ir_op_t *ops;
    size_t n_ops;
    size_t cap_ops;
} re_ir_block_t;

// A whole function's lowering. The IR is per function, never per image, so an
// emitter can work on one function at a time and stay inside a small arena.
typedef struct {
    uint64_t entry;
    uint64_t end;
    re_ir_block_t *blocks;
    size_t n_blocks;
    size_t cap_blocks;
    re_varnode_t *params;
    size_t n_params;
    re_varnode_t *rets;
    size_t n_rets;
    uint32_t frame_size; // stack frame bytes, 0 when there is no frame
} re_ir_func_t;

// The transfer function for one instruction. Architectures fill this in; the
// core never learns what a MOV or an LDR means.
typedef struct {
    uint8_t insn_id;     // architecture specific opcode enum
    uint16_t ops;        // number of re_ir_op_t entries produced
    uint16_t p0, p1, p2; // input varnodes the instruction consumed
    uint8_t out_space;
    uint8_t out_size;
} re_trfunc_t;

typedef const re_trfunc_t *(*re_trfunc_lookup)(void *arch, uint8_t insn_id);

// Free a lowering, which only ever resets the arena it came from. Present so
// callers do not reach for free() on a span they do not own.
void re_ir_release(re_arena_t *a, re_ir_func_t *f);

// ---- storage, all of it from the caller's arena ----

void re_ir_func_init(re_ir_func_t *f);

// Open a basic block at start and make it the block new ops land in.
re_ir_block_t *re_ir_block_begin(re_ir_func_t *f, re_arena_t *a, uint64_t start, uint64_t size);

// Close the open block, stamping it with the bytes consumed since it began.
void re_ir_block_end(re_ir_func_t *f);

// Append one op to the open block. Returns NULL when there is no open block, or
// when the arena is exhausted, which is not a crash and not an error to report.
re_ir_op_t *re_ir_emit(re_ir_func_t *f, re_arena_t *a, re_ir_op_t op);

re_varnode_t re_ir_vn(uint8_t space, uint16_t size, uint16_t offset);

// An op with every input and both payloads zeroed, so a backend only names the
// operands it actually produces.
re_ir_op_t re_ir_mkop(re_ir_op_t op);
#ifdef __cplusplus
}
#endif
