// re_demangle.h - C++ symbol demangling. Itanium and Microsoft, no dependencies.
// Module: feature (C11).
// Owns: both demanglers and the dispatch that picks between them.
// Depends: re_arena, re_strbuf. No I/O, no globals, bounded output always.
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"

#define RE_DEMANGLE_MAX 4096

typedef enum {
    RE_MANGLE_UNKNOWN = 0,
    RE_MANGLE_ITANIUM,
    RE_MANGLE_MSVC,
    RE_MANGLE_RUST, // the v0 scheme, or the legacy spelling with its hash
} re_mangle_t;

// Classify a symbol without demangling it.
re_mangle_t re_mangle_kind(const char *sym, size_t n);

// The scheme's name, for a report. Never NULL. One definition, so a report cannot call a
// scheme something the classifier does not.
static inline const char *re_mangle_name(re_mangle_t kind) {
    static const char *const kNames[] = {"none", "itanium", "msvc", "rust"};
    size_t k = (size_t)kind;
    return k < sizeof(kNames) / sizeof(kNames[0]) ? kNames[k] : "none";
}

// Demangle into the caller's arena. Returns false when the symbol is not a
// recognised mangled name, in which case out is left empty and the caller should
// print the original. Never fails on malformed input, only refuses it.
bool re_demangle(re_arena_t *a, const char *sym, size_t n, re_str_t *out);

// Itanium ABI, for ELF and for MinGW and clang targets. Handles the common
// <name><bare-function-type><encoding> shape with nested names and templates,
// which covers the overwhelming majority of real symbols.
bool re_demangle_itanium(re_arena_t *a, const char *sym, size_t n, re_str_t *out);

// Microsoft decorated form: ?func@@YAXXZ, ?func@class@@QEAAHH@Z and the
// ?AV and ?AU type encodings.
bool re_demangle_msvc(re_arena_t *a, const char *sym, size_t n, re_str_t *out);

// Rust, both spellings. The v0 scheme (_R...) is read directly, with the crate and impl
// disambiguators dropped because a reader needs the path rather than the identity of the
// crate instance that produced it. The legacy scheme (_ZN...17h<hash>E) is the Itanium
// spelling with the compiler's own hash appended, and the hash is what an item is not
// called, so it is dropped. Anything outside these two is refused rather than guessed at.
bool re_demangle_rust(re_arena_t *a, const char *sym, size_t n, re_str_t *out);
