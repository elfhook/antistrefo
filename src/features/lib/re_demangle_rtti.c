// re_demangle_rtti.c - reading the class names an image's RTTI carries.
// Module: feature (C11).
// Owns: the type descriptor wrapper and the scope separator inside it.
// Depends: re_demangle_rtti, re_demangle. Refuses what it does not recognise.
#include "features/lib/re_demangle_rtti.h"

#include <string.h>

#include "features/lib/re_demangle.h"

// The four kinds a type descriptor can name. A fifth, .?BA, introduces a base class
// descriptor rather than a type, and is deliberately not here: its payload is a
// different structure and reading it as a name would produce one.
static bool kind_ok(char k) {
    return k == 'V' || k == 'U' || k == 'T' || k == 'W';
}

bool re_rtti_kind(const char *sym, size_t n) {
    // ".?AV" is four bytes, a name of at least one character, and the closing "@@".
    if (n < 8)
        return false;
    if (sym[0] != '.' || sym[1] != '?' || sym[2] != 'A')
        return false;
    if (!kind_ok(sym[3]))
        return false;
    return sym[n - 2] == '@' && sym[n - 1] == '@';
}

// @@ separates scopes in a qualified name. A single @ is a back reference and is left
// alone: it stands for a scope already written, and expanding it without the name it
// refers to would invent one.
static re_str_t scope_sep(re_arena_t *a, re_str_t inner) {
    // One byte more than the input, and a terminator written. The result is a span, but
    // every caller treats the pointer as a C string, so it has to be one: an arena
    // block carries whatever the previous use left after it, and a name that ends
    // correctly but is not terminated reads on into that.
    char *buf = (char *)re_arena_alloc(a, inner.n + 1u);
    if (!buf)
        return re_str("");
    size_t w = 0;
    for (size_t i = 0; i < inner.n; i++) {
        if (inner.p[i] == '@' && i + 1u < inner.n && inner.p[i + 1] == '@') {
            buf[w++] = ':';
            buf[w++] = ':';
            i++;
        } else {
            buf[w++] = inner.p[i];
        }
    }
    buf[w] = '\0';
    return re_strn(buf, w);
}

bool re_demangle_rtti(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    if (!re_rtti_kind(sym, n))
        return false;
    re_str_t inner = re_strn(sym + 4, n - 6u);
    if (inner.n == 0)
        return false;
    if (re_demangle(a, inner.p, inner.n, out) && out->n)
        return true;
    for (size_t i = 0; i + 1u < inner.n; i++) {
        if (inner.p[i] == '@' && inner.p[i + 1] == '@') {
            re_str_t s = scope_sep(a, inner);
            if (!s.n)
                return false;
            *out = s;
            return true;
        }
    }
    *out = re_strn(re_arena_strndup(a, inner.p, inner.n), inner.n);
    return true;
}
