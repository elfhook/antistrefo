// re_vtable.h - C++ vtables and the RTTI that names them.
// Module: feature (C11).
// Owns: finding vtables, the class each belongs to, and the hierarchy between them.
// Depends: re_pe, re_code, re_demangle. Detection is structural, so a name is only
//           reported where the linker wrote one that agrees with itself.
//
// Devirtualisation needs three things and each is checked against its own claim. A
// vtable is an array of code pointers in a data section; the slot before its first
// entry points at a Complete Object Locator; the locator's pSelf field is the rva of
// the locator itself. That last check is what makes this trustworthy rather than a
// guess: a false positive cannot name a class, because a wrong pSelf fails it.
//
// A binary built without RTTI keeps its vtables and loses its names, so the two are
// reported separately and a vtable with no class is a finding rather than a failure.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

// A base class in the chain a Complete Object Locator carries.
typedef struct {
    uint32_t type_rva; // rva of the base's TypeDescriptor
    int32_t this_off;  // where the base subobject sits inside the derived object
    re_str_t name;     // demangled, empty when the binary has no RTTI
} re_base_t;

// One vtable: where it is, how many entries it has, and which class it is for.
typedef struct {
    uint32_t rva;       // of the first virtual function slot
    uint32_t col_rva;   // of the Complete Object Locator, 0 when there is none
    uint32_t td_rva;    // of the TypeDescriptor, 0 when there is none
    uint32_t n_entries; // code pointers before the run ends
    bool demangled;     // the class name was read, not guessed
    re_str_t name;      // "ns::Class", empty when there is no RTTI
    uint32_t n_bases;
    re_base_t *bases; // n_bases entries, owned by the arena
} re_vtable_t;

typedef struct {
    re_vec_t vtables; // re_vtable_t
    uint32_t n_col;   // complete object locators found
    uint32_t n_named; // of those, how many carried a readable class name
} re_vset_t;

// Find every vtable the image supports. Reads only inside mapped sections and never
// trusts a count from the file, so a malformed image yields fewer vtables, not a
// crash and not a name.
void re_vtable_scan(const re_pe_t *pe, const re_code_t *code, re_arena_t *a, re_vset_t *out);

// True when the rva holds a Complete Object Locator, judged by its own pSelf. This is
// the check the whole module rests on, so it is exposed and tested on its own.
bool re_vtable_col_at(const re_pe_t *pe, uint32_t rva, uint32_t *td_rva, uint32_t *bcd_rva);

// Entry i of a vtable, as an rva into the image. A caller reporting the targets of a
// class needs these and should not have to re-read the file itself.
bool re_vtable_entry(const re_pe_t *pe, const re_vtable_t *v, uint32_t i, uint32_t *out);

#ifdef __cplusplus
}
#endif
