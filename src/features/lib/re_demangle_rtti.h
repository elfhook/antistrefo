// re_demangle_rtti.h - the class names that appear in an image's RTTI.
// Module: feature (C11).
// Owns: reading a type descriptor name, which is not a function symbol.
// Depends: re_demangle for the inner text, which may itself be a mangled member.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"

// True when the text is an MSVC type descriptor name. Those look like ".?AVFoo@@",
// where the letter after .?A is the kind: V a class, U a struct, T a union, W an enum.
bool re_rtti_kind(const char *sym, size_t n);

// The class name inside a type descriptor. A descriptor for a template names a member
// rather than the class, and that inner text is a mangled symbol in its own right, so
// it is demangled when it can be. Otherwise it is the qualified class name with @@
// reading as ::. Refuses anything that is not a descriptor rather than guessing.
bool re_demangle_rtti(re_arena_t *a, const char *sym, size_t n, re_str_t *out);
#ifdef __cplusplus
}
#endif
