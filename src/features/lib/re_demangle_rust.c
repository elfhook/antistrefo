// re_demangle_rust.c - the Rust entry point: the v0 reader and the legacy hash form.
// Module: feature (C11).
// Owns: choosing between the two Rust spellings, and the legacy hash strip.
// Depends: re_demangle.h and the private v0 header. The v0 reader itself lives in
//           re_demangle_v0.c and re_demangle_v0_types.c; this file is the way in.
#include "features/lib/re_demangle.h"

#include <stddef.h>

#include "features/lib/re_demangle_v0.h"

// A legacy name: the Itanium spelling with the compiler's own hash appended. The hash
// distinguishes two items that are otherwise spelled the same, and it is the part a reader
// does not need, so it is dropped the way Rust drops it in a backtrace. The hash is a name
// component to the Itanium reader, which is why this cannot be done there.
static bool rust_legacy(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    re_str_t full;
    size_t cut;
    if (!re_demangle_itanium(a, sym, n, &full))
        return false;
    cut = full.n;
    *out = full;
    // The hash is spelled "::h" and sixteen hex digits at the end of the name. A name
    // ending in anything else is left whole rather than cut to a length that happens to
    // look right.
    if (cut < 19u || full.p[cut - 19u] != ':' || full.p[cut - 18u] != ':' ||
        full.p[cut - 17u] != 'h')
        return true;
    for (size_t i = cut - 16u; i < cut; i++) {
        char c = full.p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return true;
    }
    // The name has to be a string in its own right and not a prefix of the longer one: a
    // caller that prints it with a length and a caller that prints it with a terminator
    // have to see the same name, and a prefix view reads as the whole of it to anything
    // that looks for the terminator.
    *out = re_str(re_arena_strndup(a, full.p, cut - 19u));
    return out->n != 0;
}

bool re_demangle_rust(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    if (n >= 2u && sym[0] == '_' && sym[1] == 'R')
        return re_v0_symbol(a, sym, n, out);
    return rust_legacy(a, sym, n, out);
}
