// re_flirt.h - FLIRT style byte pattern library matching over function starts.
// Module: feature (C11).
// Owns: the pattern matcher, the built in idiom set, and signature file loading.
// Depends: re_code, re_func, re_vec. A pattern either matches or it does not; no
//           pattern is ever applied loosely enough to "roughly" hit.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_code.h"
#include "features/re_func.h"
#include "utils/re_arena.h"
#include "utils/re_str.h"
#include "utils/re_vec.h"

// A signature is hex bytes where '?' skips one byte. slack is how many bytes at
// the end may differ, which is what lets one pattern cover a prologue that ends
// in a variable stack adjustment. A pattern with slack is a weaker claim, so the
// caller can see it.
typedef struct {
    re_str_t name;
    re_str_t module;
    re_str_t pattern;
    uint8_t slack;
} re_sig_t;

// True when the function's opening bytes match. Only the first pattern length is
// compared; anything beyond it is left to the slack.
bool re_sig_match(const re_code_t *c, uint64_t va, const re_sig_t *sig);

// Name a function from the first signature that matches. Returns false when none
// does, and the caller must then leave the function unnamed. The set is passed in
// rather than built here, so it is read once per image instead of once per
// function.
bool re_flirt_name(const re_code_t *c, const re_func_t *f, const re_vec_t *sigs, re_str_t *name,
                   re_str_t *module);

// The built in set: structural compiler idioms rather than library code. Naming a
// library function needs a real signature database loaded from a file; inventing
// one here would put confident wrong names into the report.
size_t re_flirt_builtin(re_arena_t *a, re_vec_t *out);

// Load a signature file. One signature per line: name : module : hex pattern, with
// # starting a comment. Blank lines are skipped. Returns the number loaded, which
// is zero when the file cannot be read rather than an error to guess around.
size_t re_flirt_load(re_arena_t *a, const char *path, re_vec_t *out);
#ifdef __cplusplus
}
#endif
