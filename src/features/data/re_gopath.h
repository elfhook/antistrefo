// re_gopath.h - the Go function table, read out of a Go binary.
// Module: feature (C11).
// Owns: locating the module table and recovering the entry points it names.
// Depends: re_buf, re_arena, re_vec, re_str. A name is reported only when every offset
//           that produced it landed inside the image, and the table is accepted only when
//           its own fields agree with each other, so a magic number that happens to
//           appear in data cannot invent functions.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

// The longest name accepted. A Go name is a package path and a function, which is
// longer than a C symbol and still nothing like unbounded.
#define RE_GO_NAME_MAX 512u
// How many entries this reader will hold. Past it the table is reported as truncated
// rather than silently shortened.
#define RE_GO_MAX 400000u
// A sanity bound on the count the header states, so a corrupted field cannot ask for a
// scan of four billion entries.
#define RE_GO_NFUNC_MAX 4000000u

typedef struct {
    uint64_t va; // the function's entry address, absolute
    re_str_t name;
} re_gosym_t;

typedef struct {
    uint32_t version; // 118 or 120, the layout that was read
    uint32_t ptr_size;
    size_t n_funcs; // entries read
    size_t n_named; // entries that carried a name
    uint64_t text_start;
    bool truncated; // the cap stopped the read
} re_goinfo_t;

// Read the Go function table, appending its entries to out in table order.
//
// text_start and text_end are the image's code window, absolute, because entries are
// stated relative to the start of that window and nothing inside the file says where it
// begins. entry_va is where the image starts executing: a table has to contain it, which
// is what pins the origin those offsets are relative to, and a table that does not is
// refused rather than read from the wrong place.
//
// False when the image has no table, and also when what was found does not hold
// together: every entry offset appears twice and the two must agree, the entries must
// be ordered by address, and at least half of them must carry a readable name. That last
// one is the check that matters, because a real table names every entry it lists, so a
// run of coincidences cannot pass it and become a function list.
bool re_gopath_scan(re_span_t img, uint64_t text_start, uint64_t text_end, uint64_t entry_va,
                    re_arena_t *a, re_vec_t *out, re_goinfo_t *info);
#ifdef __cplusplus
}
#endif
