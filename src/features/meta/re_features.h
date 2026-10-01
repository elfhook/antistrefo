// re_features.h - names the optional capabilities this build was compiled with.
// Module: feature (C11).
// Owns: the feature enumeration contract. `antistrefo info` and tools/list use it.
// Depends: none. No I/O, no globals, no allocation.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

// Name of feature at index, or NULL past the end. Iterate until NULL.
const char *re_features_name(size_t index);

size_t re_features_count(void);

// True when the build includes that feature, for example "disasm".
bool re_features_has(const char *name);
#ifdef __cplusplus
}
#endif
