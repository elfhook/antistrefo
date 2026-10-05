// re_demangle_kind.c - classifying a mangled symbol, then dispatching to its reader.
// Module: feature (C11).
// Owns: the scheme classifier, the legacy Rust hash shape, and the dispatch entry point.
// Depends: re_demangle.h and the reader files the dispatch reaches. No state, no I/O.
#include "features/lib/re_demangle.h"
#include "features/lib/re_demangle_rtti.h"

#include <stddef.h>

// A legacy Rust name is an Itanium name with the compiler's own hash appended: "17h" and
// sixteen hex digits, right before the closing E. No C++ compiler produces that shape,
// which is what makes the two tellable apart without ambiguity. The shape is checked here
// rather than in a function of its own because it is only ever asked once, by this test.
static bool rust_legacy_shape(const char *sym, size_t n) {
    size_t i;
    if (n < 21u || sym[0] != '_' || sym[1] != 'Z' || sym[n - 1u] != 'E')
        return false;
    if (sym[n - 20u] != '1' || sym[n - 19u] != '7' || sym[n - 18u] != 'h')
        return false;
    for (i = n - 17u; i < n - 1u; i++) {
        char c = sym[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

re_mangle_t re_mangle_kind(const char *sym, size_t n) {
    if (n >= 3 && sym[0] == '_' && sym[1] == 'R')
        return RE_MANGLE_RUST;
    if (rust_legacy_shape(sym, n))
        return RE_MANGLE_RUST;
    if (n >= 3 && sym[0] == '_' && sym[1] == 'Z')
        return RE_MANGLE_ITANIUM;
    if (n >= 3 && sym[0] == '_' && (sym[1] == 'G' || sym[1] == 'T'))
        return RE_MANGLE_ITANIUM;
    if (n >= 2 && sym[0] == '?')
        return RE_MANGLE_MSVC;
    if (n >= 3 && sym[0] == '@' && sym[1] == '?')
        return RE_MANGLE_MSVC;
    return RE_MANGLE_UNKNOWN;
}

bool re_demangle(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    switch (re_mangle_kind(sym, n)) {
        case RE_MANGLE_ITANIUM:
            return re_demangle_itanium(a, sym, n, out);
        case RE_MANGLE_MSVC:
            return re_demangle_msvc(a, sym, n, out);
        case RE_MANGLE_RUST:
            return re_demangle_rust(a, sym, n, out);
        default:
            return re_demangle_rtti(a, sym, n, out);
    }
}
