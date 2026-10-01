// re_demangle.c - Itanium ABI demangling, the common cases done honestly.
// Module: feature (C11).
// Owns: the Itanium parser, the substitution pool, and the dispatch entry point.
// Depends: re_demangle.h only. Output bounded, no globals beyond const tables.
#include "features/lib/re_demangle.h"

#include <stddef.h>
#include <stdio.h>

#include "utils/text/re_strbuf.h"

// Itanium builtin type codes mapped to their C spelling. Emitting the ABI
// character instead of the type name would be technically parsed and useless
// to a reader, which is the whole point of demangling.
static const char *const kBuiltinTypes[] = {"v", "void",        "w",  "wchar_t",
                                            "b", "bool",        "c",  "char",
                                            "a", "signed char", "h",  "unsigned char",
                                            "s", "short",       "t",  "unsigned short",
                                            "i", "int",         "j",  "unsigned int",
                                            "l", "long",        "m",  "unsigned long",
                                            "x", "long long",   "y",  "unsigned long long",
                                            "n", "__int128",    "o",  "unsigned __int128",
                                            "f", "float",       "d",  "double",
                                            "e", "long double", "g",  "__float128",
                                            "z", "...",         NULL, NULL};

static const char *const kClassTypes[] = {"v", "w", NULL};

static const char *const kQualifiers[] = {"r", "V", "K", NULL};

#define IT_MAX_DEPTH 96

typedef struct {
    const char *p;
    const char *end;
    re_strbuf_t out;
    re_strbuf_t params; // collected separately so the caller can wrap them
    re_strbuf_t *sink;  // where it_put* currently writes
    re_vec_t subs;      // re_str_t, the substitution pool in first seen order
    re_arena_t *a;
    unsigned depth;
    bool ok;
    bool discard; // parse a type but do not render it, for return values
} it_t;

// The substitution pool is component order, which is what S_, S0_ and S1_ index.
// This is an approximation: a name that appears twice in a template prefix is
// not deduplicated exactly as the ABI does. It resolves correctly for the common
// shapes and, crucially, never produces a confident wrong answer.
static void subs_add(it_t *s, re_str_t v) {
    for (size_t i = 0; i < RE_VEC_LEN(&s->subs); i++) {
        if (re_str_eq(RE_VEC_AT(&s->subs, re_str_t, i), v))
            return;
    }
    RE_VEC_PUSH(&s->subs, s->a, v);
}

static bool subs_get(it_t *s, unsigned idx, re_str_t *out) {
    if (idx >= RE_VEC_LEN(&s->subs))
        return false;
    *out = RE_VEC_AT(&s->subs, re_str_t, idx);
    return true;
}

static void it_puts(it_t *s, const char *t) {
    if (s->ok && !s->discard)
        re_strbuf_puts(s->sink, t);
}

static void it_putn(it_t *s, const char *p, size_t n) {
    if (s->ok && !s->discard)
        re_strbuf_append(s->sink, p, n);
}

static const char *it_from(const char *p, const char *const set[]) {
    for (size_t i = 0; set[i]; i++) {
        if (p[0] == set[i][0])
            return set[i];
    }
    return NULL;
}

// The C spelling for an Itanium builtin type code, or NULL when it is not one.
static const char *it_builtin_name(const char *p) {
    for (size_t i = 0; kBuiltinTypes[i]; i += 2) {
        if (kBuiltinTypes[i][0] == p[0] && kBuiltinTypes[i][1] == '\0')
            return kBuiltinTypes[i + 1];
    }
    return NULL;
}

static void it_type(it_t *s, const char **in);

static void it_source_name(it_t *s, const char **in) {
    const char *p = *in;
    if (p >= s->end) {
        s->ok = false;
        return;
    }
    if (*p < '0' || *p > '9') {
        s->ok = false;
        return;
    }
    unsigned len = 0;
    while (p < s->end && *p >= '0' && *p <= '9') {
        len = len * 10u + (unsigned)(*p - '0');
        p++;
        if (len > 4096) {
            s->ok = false;
            return;
        }
    }
    if (p + len > s->end) {
        s->ok = false;
        return;
    }
    it_putn(s, p, len);
    subs_add(s, re_strn(p, len));
    *in = p + len;
}

static void it_template_args(it_t *s, const char **in) {
    (*in)++;
    if (**in == 'E') {
        (*in)++;
        it_puts(s, "<>");
        return;
    }
    it_puts(s, "<");
    bool first = true;
    while (s->ok && **in != 'E' && *in < s->end) {
        if (!first)
            it_puts(s, ", ");
        first = false;
        it_type(s, in);
    }
    if (!s->ok)
        return;
    if (*in < s->end && **in == 'E')
        (*in)++;
    else
        s->ok = false;
    it_puts(s, ">");
}

static void it_type(it_t *s, const char **in) {
    const char *p = *in;
    if (p >= s->end) {
        s->ok = false;
        return;
    }
    if (*p >= '0' && *p <= '9') {
        // Function type: <return><args>E. The return value is dropped, since a
        // bare identifier here is a substitution we would otherwise misread.
        while (p < s->end && *p >= '0' && *p <= '9')
            p++;
        const char *argp = p;
        while (argp < s->end && *argp != 'E')
            it_type(s, &argp);
        if (!s->ok)
            return;
        if (argp < s->end)
            argp++;
        *in = argp;
        return;
    }
    if (*p == 'S') {
        s->depth++;
        if (s->depth > IT_MAX_DEPTH) {
            s->ok = false;
            return;
        }
        while (s->ok && **in == 'S' && *in < s->end) {
            const char *cv = it_from(*in, kClassTypes);
            if (cv) {
                it_puts(s, cv);
                (*in)++;
                while (s->ok && it_from(*in, kQualifiers))
                    (*in)++;
                continue;
            }
            (*in)++;
            it_type(s, in);
        }
        if (s->ok && *in < s->end && **in == 'E') {
            (*in)++;
            s->depth--;
        }
        return;
    }
    if (*p == 'I') {
        it_template_args(s, in);
        return;
    }
    if (*p == 'P') {
        (*in)++;
        it_type(s, in);
        if (s->ok && *in < s->end && **in == 'E')
            (*in)++;
        else
            s->ok = false;
        return;
    }
    if (*p == 'T') {
        // T_ and T<n>_ are template parameters. The substituted type is not in
        // the symbol, so say auto rather than invent a name or fail outright.
        const char *q = p + 1;
        if (q < s->end && *q == '_') {
            *in = q + 1;
            it_puts(s, "auto");
            return;
        }
        unsigned v = 0;
        while (q < s->end && *q >= '0' && *q <= '9') {
            v = v * 10u + (unsigned)(*q - '0');
            q++;
            if (v > 100000) {
                s->ok = false;
                return;
            }
        }
        if (q < s->end && *q == '_') {
            *in = q + 1;
            it_puts(s, "auto");
            return;
        }
        // Otherwise it is a function type that takes the template parameter.
        (*in)++;
        while (s->ok && *in < s->end && **in >= '0' && **in <= '9')
            (*in)++;
        while (s->ok && it_from(*in, kQualifiers))
            (*in)++;
        it_type(s, in);
        return;
    }
    if (*p == 'M') {
        (*in)++;
        it_type(s, in);
        return;
    }
    if (*p == 'D') {
        (*in)++;
        it_type(s, in);
        while (s->ok && *in < s->end && **in != 'E')
            it_type(s, in);
        if (s->ok && *in < s->end && **in == 'E')
            (*in)++;
        return;
    }
    const char *bt = it_builtin_name(p);
    if (bt) {
        it_puts(s, bt);
        (*in)++;
        return;
    }
    s->ok = false;
}

static void it_name(it_t *s, const char **in) {
    if (*in >= s->end) {
        s->ok = false;
        return;
    }
    if (**in == 'N') {
        s->depth++;
        if (s->depth > IT_MAX_DEPTH) {
            s->ok = false;
            return;
        }
        (*in)++;
        // A nested name component may be a plain source name or a
        // substitution, so dispatch rather than assuming digits.
        if (*in < s->end && **in >= '0' && **in <= '9')
            it_source_name(s, in);
        else
            it_name(s, in);
        if (s->ok && *in < s->end && **in == 'I')
            it_template_args(s, in);
        // Nested components are separated by the scope resolution operator, so
        // N3foo3barE renders as foo::bar and not foobar.
        while (s->ok && *in < s->end && **in != 'E') {
            it_puts(s, "::");
            it_name(s, in);
            // Template arguments attach to the component they follow, so a
            // member function template renders as foo::bar<int>.
            if (s->ok && *in < s->end && **in == 'I')
                it_template_args(s, in);
        }
        if (!s->ok)
            return;
        if (*in < s->end && **in == 'E')
            (*in)++;
        s->depth--;
        return;
    }
    if (**in == 'Z') {
        (*in)++;
        it_puts(s, "~");
        it_name(s, in);
        return;
    }
    if (**in == 'S') {
        const char *q = *in + 1;
        unsigned idx = 0;
        if (q < s->end && *q == '_') {
            idx = 0;
        } else {
            unsigned v = 0;
            while (q < s->end && *q >= '0' && *q <= '9') {
                v = v * 10u + (unsigned)(*q - '0');
                q++;
                if (v > 100000) {
                    s->ok = false;
                    return;
                }
            }
            if (q >= s->end || *q != '_') {
                s->ok = false;
                return;
            }
            idx = v + 1u;
        }
        q++;
        re_str_t v;
        if (!subs_get(s, idx, &v)) {
            s->ok = false;
            return;
        }
        it_putn(s, v.p, v.n);
        *in = q;
        return;
    }
    it_source_name(s, in);
}

// The bare function type is <return><params>. The return is consumed and
// discarded, because a symbol does not carry enough information to name it.
// A bare v as the whole list means no parameters at all.
static void it_params(it_t *s, const char **in) {
    if (*in >= s->end) {
        s->ok = false;
        return;
    }
    if (**in == 'v' && *in + 1 == s->end) {
        (*in)++;
        return;
    }
    // Return type, parsed but never rendered. A symbol does not carry enough
    // information to name it, so printing it would be a confident guess.
    if (**in == 'S' && *in + 1 < s->end && (*in)[1] == '_') {
        *in += 2;
    } else {
        s->discard = true;
        it_type(s, in);
        s->discard = false;
    }
    if (!s->ok)
        return;
    bool first = true;
    s->sink = &s->params;
    while (s->ok && *in < s->end) {
        if (!first)
            it_puts(s, ", ");
        first = false;
        // A substitution reference in the parameter list resolves the same way
        // it does inside a name.
        if (**in == 'S' && *in + 1 < s->end && (*in)[1] == '_') {
            re_str_t v;
            if (!subs_get(s, 0, &v)) {
                s->ok = false;
                s->sink = &s->out;
                return;
            }
            it_putn(s, v.p, v.n);
            *in += 2;
            continue;
        }
        it_type(s, in);
    }
    s->sink = &s->out;
}

bool re_demangle_itanium(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    it_t s;
    s.p = sym;
    s.end = sym + n;
    s.a = a;
    s.depth = 0;
    s.ok = true;
    // Discard has to start false. Leaving it to the stack made the second
    // demangle in a process inherit the first one's leftover, and a stale true
    // suppressed the name so the call reported failure for a valid symbol.
    s.discard = false;
    re_vec_init(&s.subs, sizeof(re_str_t));
    re_strbuf_init(&s.out, a);
    re_strbuf_init(&s.params, a);
    s.sink = &s.out;
    const char *p = sym;
    // Strip the mangling prefix: _Z for ELF, __Z for Mach-O which adds its own
    // leading underscore. Advancing by the wrong amount lands on the Z, which
    // then parses as a local scope name and prefixes the result with a tilde.
    if (s.end - s.p >= 3 && s.p[0] == '_' && s.p[1] == '_' && s.p[2] == 'Z')
        p = s.p + 3;
    else if (s.end - s.p >= 2 && s.p[0] == '_' && s.p[1] == 'Z')
        p = s.p + 2;
    it_name(&s, &p);
    if (!s.ok || p >= s.end)
        return false;
    // The underscore separating a name from its parameters is present only when
    // the encoding actually carries one, so it must be optional.
    if (*p == '_')
        p++;
    it_params(&s, &p);
    if (!s.ok)
        return false;
    // A function always renders a parameter list, even an empty one, and the
    // types were collected separately so they can be wrapped here.
    it_puts(&s, "(");
    if (s.params.p && s.params.len)
        re_strbuf_append(&s.out, s.params.p, s.params.len);
    it_puts(&s, ")");
    // A trailing cv qualifier and ref qualifier are not worth reproducing.
    while (p < s.end && (*p == 'C' || *p == 'D' || *p == 'R' || *p == 'O'))
        p++;
    if (p != s.end)
        return false;
    char *text = re_strbuf_detach(&s.out);
    if (!text || re_str(text).n == 0)
        return false;
    *out = re_str(text);
    return true;
}

re_mangle_t re_mangle_kind(const char *sym, size_t n) {
    if (n >= 3 && sym[0] == '_' && sym[1] == 'Z')
        return RE_MANGLE_ITANIUM;
    if (n >= 3 && sym[0] == '_' && (sym[1] == 'Z' || sym[1] == 'G' || sym[1] == 'T') &&
        sym[2] != '\0')
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
        default:
            return false;
    }
}
