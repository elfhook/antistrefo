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

#include "utils/mem/re_buf.h"

// Where a varnode lives. Side effects are explicit in the IR, never implied by a
// register, which is what lets an emulator and a decompiler share one lowering.
typedef enum {
    RE_SPACE_CONST = 0, // literal, no storage
    RE_SPACE_REG,       // architectural register
    RE_SPACE_STACK,     // stack slot, offset relative to the frame
    RE_SPACE_HEAP,      // memory at an address in a register or constant
    RE_SPACE_UNIQUE,    // SSA style temporary
    RE_SPACE_IOP,       // an I/O register, never mapped to normal memory
    RE_SPACE_FLAG,      // one architectural flag bit, named by its offset
} re_space_t;

// The flag bits, as offsets inside RE_SPACE_FLAG. A lowering that computes a
// carry writes them; a lowering that consumes one reads them. The emitter hides
// the writes and folds the reads into printed conditions wherever it can.
typedef enum {
    RE_FLAG_CF = 0, // carry
    RE_FLAG_ZF,     // zero
    RE_FLAG_SF,     // sign
    RE_FLAG_OF,     // overflow
    RE_FLAG_PF,     // parity
    RE_FLAG_AF,     // adjust
    RE_FLAG_COUNT
} re_flag_t;

typedef struct {
    uint16_t size;   // bytes, 1, 2, 4, 8 or 16
    uint16_t offset; // register index, stack offset, or nothing
    uint8_t space;
} re_varnode_t;

// The kind of an op, kept distinct from re_ir_op_t which is the op itself.
// The arithmetic and comparison ops arrived in task 4, when the emitter needed
// them: without them an expression cannot be written at all, because a register
// transfer language with only CONST and VAR can only move values around.
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
    RE_OP_INTADD,     // out := in0 + in1
    RE_OP_INTSUB,     // out := in0 - in1
    RE_OP_INTMUL,     // out := in0 * in1
    RE_OP_INTDIV,     // out := in0 / in1, signed
    RE_OP_INTMOD,     // out := in0 % in1, signed
    RE_OP_INTAND,     // out := in0 & in1
    RE_OP_INTOR,      // out := in0 | in1
    RE_OP_INTXOR,     // out := in0 ^ in1
    RE_OP_INTSHL,     // out := in0 << in1
    RE_OP_INTSHR,     // out := in0 >> in1, logical
    RE_OP_INTSAR,     // out := in0 >> in1, arithmetic, in0 read as signed
    RE_OP_INTNEG,     // out := -in0
    RE_OP_INT2BOOL,   // out := in0 != 0
    RE_OP_SLICE,      // out := the low const_val bytes of in0
    RE_OP_CAST,       // out := in0 widened or narrowed to out.size
    RE_OP_CMP,        // out := the comparison, in extra as the condition code
    RE_OP_INTUDIV,    // out := in0 / in1, unsigned
    RE_OP_INTUMOD,    // out := in0 % in1, unsigned
    RE_OP_UMULH,      // out := the high half of in0 * in1, unsigned
    RE_OP_IMULH,      // out := the high half of in0 * in1, signed
    RE_OP_ROL,        // out := in0 rotated left by in1
    RE_OP_ROR,        // out := in0 rotated right by in1
    RE_OP_POPCNT,     // out := the number of set bits in in0
    RE_OP_LZCNT,      // out := the number of leading zero bits in in0
    RE_OP_TZCNT,      // out := the number of trailing zero bits in in0
    RE_OP_BSWAP,      // out := in0 byte reversed
    RE_OP_BITNOT,     // out := ~in0
    RE_OP_SELECT,     // out := in1 when the condition holds else in0, cc in extra
    RE_OP_SETCC,      // out := the condition in extra as 0 or 1
    RE_OP_FADD,       // float add
    RE_OP_FSUB,       // float subtract
    RE_OP_FMUL,       // float multiply
    RE_OP_FDIV,       // float divide
    RE_OP_FCAST,      // out := in0 converted between integer and float
    RE_OP_MEMCPY,     // memcpy(in0, in1, in2): a rep move, not a C call
    RE_OP_MEMSET,     // memset(in0, in1, in2): a rep store, not a C call
    RE_OP_NOP,        // an instruction the arch knows and nothing else does
// Set in a CONST op's extra field when the constant exists only to be an operand of a
// later op. The emitter uses it to decide between printing the value inline, which is
// what a mov of an immediate does, and folding it away, which is what an address or
// an immediate operand does. Guessing that from the op stream alone needs a lookahead
// past one op, and a read modify write pushes the operand several ops ahead.
#define RE_CONST_OPERAND 1u
// Set in a CAST op's extra field when the widening is signed. A movzx and a movsx
// differ only in that bit, and printing the wrong one is a silent wrong answer
// about every negative number that passes through a byte or a word.
#define RE_CAST_SIGNED 2u

} re_op_kind_t;

// What the emitter knows about the instruction whose flags a branch reads. The
// hidden comparison a lowering emits before a flag setting operation carries one
// of these, and the branch's own condition nibble is interpreted against it:
// the same JE means one thing after CMP and another after ADD.
typedef enum {
    RE_SETF_CMP = 0, // a real comparison: full condition set derivable
    RE_SETF_TEST,    // a test: zero and sign of (a & b)
    RE_SETF_SUB,     // a subtraction: zero and sign of the result
    RE_SETF_ADD,     // an addition: zero and sign of the result
    RE_SETF_LOGIC,   // and, or, xor: zero and sign of the result
    RE_SETF_SHIFT,   // a shift: zero and sign of the result
    RE_SETF_NEG,     // a negation: zero and sign of the result
    RE_SETF_INCDEC,  // inc or dec: zero and sign of the result, carry untouched
    RE_SETF_COUNT
} re_setf_t;

// The x86 condition nibble, named so an emitter's table reads as the architecture
// manual rather than as a set of mystery constants. A branch opcode's low four
// bits are exactly one of these.
typedef enum {
    RE_CC_JO = 0,
    RE_CC_JNO,
    RE_CC_JB,
    RE_CC_JAE,
    RE_CC_JE,
    RE_CC_JNE,
    RE_CC_JBE,
    RE_CC_JA,
    RE_CC_JS,
    RE_CC_JNS,
    RE_CC_JP,
    RE_CC_JNP,
    RE_CC_JL,
    RE_CC_JGE,
    RE_CC_JLE,
    RE_CC_JG,
} re_cc_t;

// The condition codes a comparison op itself computes, for the backends that
// compute a comparison rather than setting flags for a later branch to read.
typedef enum {
    RE_CC_OP_EQ = 0,
    RE_CC_OP_NE,
    RE_CC_OP_SLT,
    RE_CC_OP_SLE,
    RE_CC_OP_ULT,
    RE_CC_OP_ULE,
    RE_CC_OP_SGT,
    RE_CC_OP_SGE,
    RE_CC_OP_UGT,
    RE_CC_OP_UGE,
} re_cond_t;

typedef struct {
    re_op_kind_t op;
    re_varnode_t out; // unused when out.space is RE_SPACE_CONST
    re_varnode_t in[4];
    int64_t const_val; // meaningful only for RE_OP_CONST
    uint32_t extra;    // space for arch specific payloads
    uint64_t addr;     // the instruction this op came from, stamped by the
                       // lowering wrapper so an annotation can find its site
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
    // A per function counter for temporaries. The IR is per function, so this is
    // where a backend keeps its numbering, and it keeps lowering stateless.
    uint32_t next_uniq;
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
