// re_cfg.h - the control flow graph of one function, as blocks and edges.
// Module: feature (C11).
// Owns: block partitioning, terminator classification, and the edge list.
// Depends: re_dc_walk, re_code, re_func, re_vec. The decoder is reached only
//           through the re_disasm_t vtable, so no x86 detail appears here.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

#define RE_CFG_MAX_BLOCKS 256

// Why a block stops. These are reasons a reader can act on, not labels: a block
// that ends in RET is closed, one that ends in CALL continues at the next block,
// and one whose terminator could not be classified is reported as unknown rather
// than silently treated as a fallthrough.
typedef enum {
    RE_CFG_TERM_FALL = 0, // runs into the next block
    RE_CFG_TERM_CALL,     // calls, then continues
    RE_CFG_TERM_COND,     // branch, two successors
    RE_CFG_TERM_JUMP,     // branch, one successor
    RE_CFG_TERM_RET,      // returns
    RE_CFG_TERM_INDIRECT, // branch with no resolvable target
    RE_CFG_TERM_CUT,      // the walk stopped here without meeting a terminator
    RE_CFG_TERM_UNKNOWN,  // the terminator could not be classified
} re_cfg_term_t;

// Why one block reaches another.
typedef enum {
    RE_CFG_EDGE_FALL = 0, // fell through to the next block
    RE_CFG_EDGE_TAKEN,    // took the branch
    RE_CFG_EDGE_TAIL,     // jumped outside the function, so it is a tail call
} re_cfg_edge_kind_t;

typedef struct {
    uint64_t va;
    uint32_t size;
    uint32_t n_insns;
    uint8_t term;    // re_cfg_term_t
    uint64_t target; // branch destination, 0 when there is none
    bool has_target;
    bool external; // the target lies outside this function
} re_cfg_block_t;

typedef struct {
    uint32_t from; // block index
    int32_t to;    // block index, or -1 when the destination was not resolved
    uint8_t kind;  // re_cfg_edge_kind_t
} re_cfg_edge_t;

typedef struct {
    re_vec_t blocks;       // re_cfg_block_t, ascending by va
    re_vec_t edges;        // re_cfg_edge_t
    uint32_t n_unknown;    // blocks whose terminator could not be classified
    uint32_t n_unresolved; // edges whose destination is not a known block
    bool truncated;        // the block cap was reached, so the graph is partial
} re_cfg_t;

// Build the graph for f by reusing the decompiler's block structure rather than
// walking the function a second time, so the graph and the emitted C always
// describe the same blocks. Returns false only when the function decoded to
// nothing at all, which is the one case where an empty graph would be a lie.
bool re_cfg_build(re_code_t *c, const re_func_t *f, re_cfg_t *out, re_arena_t *a);

// The name of a terminator kind, for the report. Never NULL.
const char *re_cfg_term_name(uint8_t term);

// The name of an edge kind, for the report. Never NULL.
const char *re_cfg_edge_name(uint8_t kind);

#ifdef __cplusplus
}
#endif
