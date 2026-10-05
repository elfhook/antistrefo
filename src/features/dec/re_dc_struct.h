// re_dc_struct.h - the structured shape of one function's control flow.
// Module: feature (C11).
// Owns: the structured printer's interface and its statistics.
// Depends: re_dc_print, re_dc_walk, re_func, re_ir.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_func.h"
#include "features/dec/re_dc_print.h"
#include "features/dec/re_dc_walk.h"
#include "features/dec/re_ir.h"

// How the emitter prints one op: the decompiler's own statement writer, passed in
// so this file stays about control structure and never learns what an op means.
typedef void (*re_dc_op_fn)(re_dc_emit_t *, const re_ir_op_t *, const re_dc_walk_t *);

// What one structured print did, in the unit each reader acts on. A count of
// ifs with no loop count hides the shape of the function, so both are reported.
typedef struct {
    bool ok;         // the function printed structured, not flat
    uint32_t n_if;   // if and if/else statements emitted
    uint32_t n_loop; // while and do statements emitted
    uint32_t n_goto; // gotos that structuring could not remove
} re_dc_struct_stat_t;

// Print the body with the gotos folded into if, else, while and do statements
// where the graph allows it, and plain gotos where it does not. The blocks come
// from the walk's own label table and the branches from the op stream, so this
// pass and the flat printer always describe the same machine: nothing is
// re-decoded and nothing the lowering folded is resurrected. Returns false when
// the body is not worth structuring, and the caller falls back to the flat
// printer; stat is always written, zeroed on false.
bool re_dc_struct_print(re_dc_emit_t *e, const re_dc_walk_t *w, const re_ir_func_t *ir,
                        const uint16_t *produced, const re_func_t *f, re_dc_op_fn emit_op,
                        re_dc_struct_stat_t *stat);
#ifdef __cplusplus
}
#endif
