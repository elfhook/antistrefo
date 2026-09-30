// re_triage.h - the single call ingest view. What an agent should run first.
// Module: feature (C11).
// Owns: risk signal classification and the triage JSON body.
// Depends: re_pe, re_strings, re_json, re_hash. No I/O, the caller flushes.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_pe.h"
#include "features/re_strings.h"
#include "utils/re_json.h"

// Kernel APIs that decide how dangerous a driver's attack surface is. This is
// policy, so it lives in one table and grows in one place.
typedef struct {
    const char *sym;
    const char *why;
    int weight;
} re_kernel_api_t;

const re_kernel_api_t *re_kernel_api_table(size_t *count);

// True when the symbol is in the table, filling why and weight when it is.
bool re_kernel_api_lookup(re_str_t sym, const char **why, int *weight);

// Emit the triage body, assuming the caller already wrote the envelope and the
// object for this payload. Writes members, no outer braces.
void re_triage_emit(re_jw_t *w, re_span_t img, const re_pe_t *pe, const re_strings_t *st,
                    re_arena_t *a);

// True when a string is a runtime format string, which means the real device
// name never appears in the file and static triage cannot resolve it.
bool re_triage_has_dynamic_device(const re_strings_t *st, uint64_t *count);
#ifdef __cplusplus
}
#endif
