// re_names.h - names and call targets recovered from the image's own tables.
// Module: feature (C11).
// Owns: vtable slot naming, the two x64 virtual call forms, and the EH scopes.
// Depends: re_code, re_func, re_pe, re_vtable, re_arena, re_vec, re_str. Sits in
//           the flow folder because a recovered call target is flow recovery:
//           the graph it feeds is the one the decompiler prints.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/data/re_vtable.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

// A class method named "ns::Class::method" is longer than any slot name a reader
// benefits from, and the tail after this many characters is repetition, not fact.
#define RE_NAMES_NAME_MAX 128u

// Caps that keep a hostile or merely enormous image from turning one pass into
// the whole analysis. Real C++ programs sit far below both.
#define RE_NAMES_MAX_SLOTS 8192u
#define RE_EH_MAX_SCOPES 16384u

// One indirect call whose target the pass recovered: the instruction, and the
// class method the slot it reads names. The name is arena owned text.
typedef struct {
    uint64_t at; // the call instruction
    re_str_t method;
} re_vcall_t;

// One try block, as the unwind metadata states it. The range is the protected
// region, which is what a reader wants; the handler itself is an address the
// metadata points at and is reported with the ranges, not here.
typedef struct {
    uint64_t begin; // first byte of the try region
    uint64_t end;   // one past the last byte of it
} re_eh_scope_t;

// What the pass did, in units a report counts.
typedef struct {
    size_t n_slots;  // vtable slots whose target function took a class name
    size_t n_funcs;  // functions carrying at least one decoded try region
    size_t n_scopes; // try regions decoded from the unwind metadata
    size_t n_vcalls; // indirect calls whose target slot was recovered
    re_vec_t vcalls; // re_vcall_t, ascending by address
    re_vec_t scopes; // re_eh_scope_t, ascending by begin
} re_names_stat_t;

// Zero the record and point its lists at the caller's arena.
void re_names_stat_init(re_names_stat_t *st, re_arena_t *a);

// Run all three recoveries over one analysed image. The function table is
// mutated: slot naming writes the class method names into it, which is the
// point, because every later consumer reads the table rather than this pass.
void re_names_apply(const re_pe_t *pe, re_code_t *code, re_fscan_t *scan, const re_vset_t *vs,
                    re_arena_t *a, re_names_stat_t *out);
#ifdef __cplusplus
}
#endif
