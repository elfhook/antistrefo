// re_flow.h - the flow recovery pass over one function's IR.
// Module: feature (C11).
// Owns: SSA bookkeeping, the value tracking rewrite, and the deobfuscation idioms.
// Depends: re_ir, re_cfg, re_code, re_arena, re_vec. Nothing here decodes an
//           instruction except through re_code_insn, so no x86 detail belongs here.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/dec/re_cfg.h"
#include "features/dec/re_ir.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

// How many cells the value tracker holds. The lower half indexes constant ids,
// the upper band indexes registers, so a register write and a constant id can
// never land on the same cell and be confused for one another.
#define RE_FLOW_MAX_KEYS 1024u

// Where the register band starts inside the cell table, offset by the space
// byte so a future second tracked space would take the band next to it.
#define RE_FLOW_REG_BASE 512u

// The longest stack string text one record carries. The pass refuses a longer
// run rather than truncate it into a different string.
#define RE_FLOW_STR_MAX 96u

// A decoded stack string: the address of the first store that built it and
// the text the stores spell. The emitter prints it as a comment, so a reader
// sees the literal the machine constructs one byte at a time.
typedef struct {
    uint64_t at;
    char text[RE_FLOW_STR_MAX];
} re_flow_str_t;

// What the rewrite pass did, in the unit each reader acts on. A count of
// transformations with no breakdown is a scoreboard nobody can argue with, so
// every idiom reports itself separately.
typedef struct {
    size_t n_const;     // arithmetic folded to a constant
    size_t n_copy;      // a register copy folded to the value it carried
    size_t n_dead;      // operand constants nothing consumed any more
    size_t n_pred;      // opaque predicates decided at compile time
    size_t n_callind;   // indirect calls whose target slot was recovered
    size_t n_thunk;     // call $+5 obfuscation trampolines removed
    size_t n_stackstr;  // stack string runs decoded
    size_t n_jtable;    // indirect dispatches bound to a jump table
    size_t n_total;     // the sum, so a caller needs no arithmetic
    re_vec_t strs;      // re_flow_str_t, the stack strings this run decoded
    re_arena_t *strs_a; // the arena the records come from, set by the caller
} re_flow_stat_t;

// ---- SSA bookkeeping ----

// One definition: where an op wrote a register, a stack slot or a temporary.
// keyid packs the space and the offset into one search key so the def-use
// query is a binary search and nothing has to be hashed.
typedef struct {
    uint64_t addr;  // the instruction that wrote it
    uint64_t keyid; // space and offset packed, the search key
    uint32_t block; // the block the defining op sits in
    uint32_t op;    // the op index, for callers that want the op itself
    uint32_t seq;   // position in the stream, which orders the chain
    uint32_t size;  // bytes written
    uint8_t space;  // re_space_t
    uint16_t key;   // the register, slot or temporary id
} re_flow_def_t;

typedef struct {
    re_vec_t defs; // re_flow_def_t, sorted by keyid then seq
} re_flow_ssa_t;

// Collect every definition in the function. When g is given, each def records
// the CFG block its defining instruction belongs to; a NULL g records zero.
void re_flow_ssa_build(const re_ir_func_t *f, const re_cfg_t *g, re_arena_t *a, re_flow_ssa_t *out);

// The previous definition of the same space and offset before d in the stream,
// or NULL when d is the first. Repeated calls walk the chain to the top.
const re_flow_def_t *re_flow_ssa_def_before(const re_flow_ssa_t *s, const re_flow_def_t *d);

// Immediate dominators over the CFG's blocks, entry first. idom holds one
// entry per block; the entry dominates itself and an unreachable block keeps
// the undefined index. Computed by the standard iterative intersection, which
// is linear here because the graphs a function produces are small.
#define RE_FLOW_IDOM_NONE 0xFFFFFFFFu
void re_flow_dominators(const re_cfg_t *g, re_arena_t *a, uint32_t *idom);

// True when block a dominates block b, which includes a == b.
bool re_flow_dominates(const uint32_t *idom, uint32_t n, uint32_t a, uint32_t b);

// ---- the rewrite pass ----

// Fold constants and copies, and decide opaque predicates whose inputs the
// pass can prove. Works on one function's IR in place; the emitter prints
// whatever is left. The per idiom counts land in st.
void re_flow_constprop(re_ir_func_t *f, re_arena_t *a, re_flow_stat_t *st);

// The deobfuscation idioms that need the image bytes rather than the IR alone:
// indirect calls whose target slot the code loaded first, call $+5 trampolines,
// and stack string runs, recorded as text for the emitter to print.
void re_flow_deobf(re_ir_func_t *f, re_code_t *code, re_arena_t *a, re_flow_stat_t *st);

// Zero a stat record and point its string list at the caller's arena. Must be
// called before the first pass runs, because the records are appended.
void re_flow_stat_init(re_flow_stat_t *st, re_arena_t *a);

// Run both over one function, deobfuscation first so the value tracking sees
// the facts the idioms recovered. code may be NULL, which limits the pass to
// what the IR alone can decide. st may be NULL when the caller only wants the
// count.
size_t re_flow_apply(re_ir_func_t *f, re_code_t *code, re_arena_t *a, re_flow_stat_t *st);

// ---- jump table resolution ----

// Bind every block the CFG left as an indirect terminator to the jump table
// that dispatches through it, when the scan found one. A block whose dispatch
// was bound becomes a plain jump to the table's first case, which is what lets
// the graph, the scoreboard and the report agree that a switch was recovered.
// Returns how many dispatches were bound.
size_t re_flow_cfg_jtables(re_cfg_t *g, const re_code_t *c, const re_vec_t *jtables, re_arena_t *a);
#ifdef __cplusplus
}
#endif
