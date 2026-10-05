// re_seeds.h - the start addresses nothing in the image points at with a branch.
// Module: feature (C11).
// Owns: import thunks, TLS callbacks, driver dispatch slots, and code pointers.
// Depends: re_code and re_pe. A seed is a candidate, never a function: the walk
//           still has to decode it before anything is reported.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h" // for the module tags a seed writes
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

// One start and what the image says about it. A seed with no name is still a start:
// a code pointer in .rdata says the compiler put a function there and says nothing
// about what it is called.
typedef struct {
    uint64_t va;
    re_str_t name;
    re_str_t module; // which structure named it: driver, irp, import, tls, pointer
} re_seed_t;

// Every start the image's own structures state: import thunks, TLS callbacks, the
// entry point of a driver, and code pointers in data. The scan is over bytes and
// tables rather than over the walk, because these are exactly the functions the
// walk cannot reach: nothing branches to them.
void re_seed_collect(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vec_t *out);

// The IRP dispatch slots a driver fills in. A single store into an eight byte slot is
// a field of some other structure, so only a run of stores into four or more different
// slots of the same object is taken as a table; that is what separates a dispatch
// routine from a counter that happens to live at the same offset.
void re_seed_irp(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vec_t *out);

// True when a module tag is one a seed wrote, which is how a later pass knows a name
// was inferred from a structure rather than read from a name table.
bool re_name_is_seed(re_str_t module);
#ifdef __cplusplus
}
#endif
