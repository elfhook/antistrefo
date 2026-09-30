// re_dc_walk.h - the block structure of one function, independent of text.
// Module: feature (C11).
// Owns: the label table and the instruction list the emitter walks.
// Depends: re_code, re_func, re_disasm, re_arena, re_vec.
// Depends: re_code, re_func. The arch is reached through the re_disasm_t vtable.
// The emitter needs this separately because the label numbering must be stable
// before any text exists, otherwise a label would be renamed every time it is used.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_code.h"
#include "features/re_disasm.h"
#include "features/re_func.h"
#include "utils/re_arena.h"
#include "utils/re_vec.h"

#define RE_DC_MAX_BLOCKS 256

typedef struct {
    uint64_t va;    // where the block starts
    uint32_t label; // the number the emitter prints after an L
} re_dc_label_t;

typedef struct {
    re_vec_t insns;   // re_insn_t, ascending by va
    re_vec_t labels;  // re_dc_label_t, ascending by va
    size_t n_unknown; // instructions the backend did not lower
} re_dc_walk_t;

// Decode the body of f, following the branches it finds and stopping at each
// terminator. The visited map is one byte per byte of the function, so a block
// reached from two predecessors is decoded once and a loop does not spin.
void re_dc_walk(re_code_t *code, const re_func_t *f, re_dc_walk_t *w, re_arena_t *a);

// The label number for a branch target, or 0 when the address is not a block start.
// Zero is not a legal label, so a caller can use it directly as "no label".
uint32_t re_dc_label_of(const re_dc_walk_t *w, uint64_t va);
#ifdef __cplusplus
}
#endif
