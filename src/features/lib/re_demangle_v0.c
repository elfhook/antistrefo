// re_demangle_v0.c - the v0 reader: cursor, identifiers, and the path productions.
// Module: feature (C11).
// Owns: reading a v0 symbol into a name, and the paths that name an entity.
// Depends: re_demangle_v0.h, re_strbuf. The type side of the grammar lives in
//           re_demangle_v0_types.c; both read through the same cursor.
#include "features/lib/re_demangle_v0.h"

bool re_v0_putc(re_v0_t *v, char c) {
    if (v->skip)
        return true;
    if (v->out.len >= RE_V0_MAX_OUT) {
        v->bad = true;
        return false;
    }
    return re_strbuf_putc(&v->out, c);
}

bool re_v0_puts(re_v0_t *v, const char *s) {
    for (size_t i = 0; s[i]; i++) {
        if (!re_v0_putc(v, s[i]))
            return false;
    }
    return true;
}

// A name from the file is text or it is not a name. Control bytes are what a wrong offset
// produces, so the check is here rather than at every call site.
bool re_v0_putn(re_v0_t *v, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] < 0x20u || p[i] == 0x7fu) {
            v->bad = true;
            return false;
        }
        if (!re_v0_putc(v, (char)p[i]))
            return false;
    }
    return true;
}

bool re_v0_put_u64(re_v0_t *v, uint64_t x) {
    char digits[24];
    size_t n = 0;
    if (x == 0)
        digits[n++] = '0';
    while (x) {
        digits[n++] = (char)('0' + (x % 10u));
        x /= 10u;
    }
    while (n) {
        if (!re_v0_putc(v, digits[--n]))
            return false;
    }
    return true;
}

// base-62-number: digits then an underscore. The digits are optional and an empty number
// is zero. A number that runs off the input is malformed rather than zero.
bool re_v0_base62(re_v0_t *v, uint64_t *out) {
    uint64_t acc = 0;
    while (v->pos < v->n) {
        uint8_t c = v->p[v->pos];
        uint64_t d;
        if (c >= '0' && c <= '9')
            d = (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'z')
            d = (uint64_t)(c - 'a') + 10u;
        else if (c >= 'A' && c <= 'Z')
            d = (uint64_t)(c - 'A') + 36u;
        else
            break;
        acc = acc * 62u + d;
        v->pos++;
    }
    if (!re_v0_eat(v, '_'))
        return false;
    *out = acc;
    return true;
}

// decimal-number: a zero, or a digit 1-9 followed by digits. A leading zero is the whole
// number, which is what keeps two identifiers in a row apart: without it, the empty name
// of one element followed by the length of the next would read as one longer number.
bool re_v0_decimal(re_v0_t *v, uint64_t *out) {
    uint64_t acc = 0;
    if (v->pos >= v->n || v->p[v->pos] < '0' || v->p[v->pos] > '9')
        return false;
    if (v->p[v->pos] == '0') {
        v->pos++;
        *out = 0;
        return true;
    }
    while (v->pos < v->n && v->p[v->pos] >= '0' && v->p[v->pos] <= '9') {
        acc = acc * 10u + (uint64_t)(v->p[v->pos] - '0');
        if (acc > 0xffffffu) {
            v->bad = true;
            return false;
        }
        v->pos++;
    }
    *out = acc;
    return true;
}

// disambiguator: "s" and a base-62-number, whose value is one more than the number.
// Absent is zero, which is why the encoding can leave it out.
bool re_v0_disamb(re_v0_t *v, uint64_t *out) {
    uint64_t raw = 0;
    if (!re_v0_eat(v, 's')) {
        *out = 0;
        return true;
    }
    if (!re_v0_base62(v, &raw))
        return false;
    *out = raw + 1u;
    return true;
}

// identifier: an optional disambiguator, then the name as a length and its bytes. A
// punycode identifier is refused rather than half decoded: it names the same item as its
// UTF-8 spelling, and printing the punycode as if it were the name would be wrong.
bool re_v0_ident(re_v0_t *v, uint64_t *dis, re_str_t *name) {
    uint64_t len = 0;
    if (!re_v0_disamb(v, dis))
        return false;
    if (re_v0_eat(v, 'u')) {
        v->bad = true;
        return false;
    }
    if (!re_v0_decimal(v, &len))
        return false;
    (void)re_v0_eat(v, '_'); // mandatory only when the bytes start with a digit or '_'
    if (v->pos + (size_t)len > v->n) {
        v->bad = true;
        return false;
    }
    name->p = (const char *)(v->p + v->pos);
    name->n = (size_t)len;
    v->pos += (size_t)len;
    return true;
}

// lifetime: an index. Zero is the erased lifetime, printed as nothing in a reference
// because that is the spelling Rust uses, and as a bare '_ elsewhere. A numbered one is
// printed numerically, which a reader can tell apart from the erased case.
bool re_v0_lifetime(re_v0_t *v, uint64_t *out) {
    if (!re_v0_eat(v, 'L'))
        return false;
    return re_v0_base62(v, out);
}

bool re_v0_lifetime_print(re_v0_t *v, uint64_t idx) {
    if (idx != 0 && !re_v0_put_u64(v, idx))
        return false;
    return re_v0_puts(v, "'_");
}

// The tail of a nested path: what the namespace and the identifier add after the parent.
static bool nested_tail(re_v0_t *v, uint8_t ns, uint64_t dis, re_str_t name) {
    // An uppercase namespace is one of the special ones: a closure, a shim, or something
    // the format added later, which is printed by its tag rather than dropped, because a
    // segment that disappears would read as a segment that is not there. The disambiguator
    // is shown even when it is zero: it is what tells two closures under one parent apart.
    if (ns >= 'A' && ns <= 'Z') {
        if (!re_v0_puts(v, "::{"))
            return false;
        if (ns == 'C')
            re_v0_puts(v, "closure");
        else if (ns == 'S')
            re_v0_puts(v, "shim");
        else if (!re_v0_putc(v, (char)ns))
            return false;
        if ((ns == 'C' || ns == 'S') && name.n &&
            (!re_v0_putc(v, ':') || !re_v0_putn(v, (const uint8_t *)name.p, name.n)))
            return false;
        if (!re_v0_putc(v, '#') || !re_v0_put_u64(v, dis) || !re_v0_putc(v, '}'))
            return false;
        return true;
    }
    // A lowercase namespace is the compiler's own bookkeeping and is not shown; an
    // unnamed element prints nothing after its parent, so no separator is written.
    if (name.n == 0)
        return true;
    if (!re_v0_puts(v, "::"))
        return false;
    return re_v0_putn(v, (const uint8_t *)name.p, name.n);
}

// The impl path in front of an inherent or trait impl: a disambiguator and a path, both
// of which say where the impl lives rather than what it is, so both are read and neither
// is shown. Skipping is parsing with the output switched off, not reading less: the bytes
// still have to hold together, or the impl after them is not the one they describe.
static bool impl_path(re_v0_t *v) {
    uint64_t dis = 0;
    bool inner = false;
    bool shown = v->skip;
    if (!re_v0_disamb(v, &dis))
        return false;
    v->skip = true;
    if (!re_v0_path(v, &inner)) {
        v->skip = shown;
        return false;
    }
    v->skip = shown;
    return true;
}

static bool path_crate(re_v0_t *v) {
    uint64_t dis = 0;
    re_str_t name;
    v->pos++; // 'C'
    if (!re_v0_ident(v, &dis, &name))
        return false;
    return re_v0_putn(v, (const uint8_t *)name.p, name.n);
}

static bool path_nested(re_v0_t *v) {
    uint8_t ns;
    uint64_t dis = 0;
    re_str_t name;
    bool inner = false;
    v->pos++; // 'N'
    ns = re_v0_peek(v);
    v->pos++;
    if (!re_v0_path(v, &inner) || !re_v0_ident(v, &dis, &name) || !nested_tail(v, ns, dis, name))
        return false;
    // A value namespace is what makes a path a function rather than a type, and that is
    // what decides whether its generic arguments are introduced with "::".
    v->value = (ns == 'v');
    return true;
}

static bool path_inherent(re_v0_t *v) {
    v->pos++; // 'M'
    if (!impl_path(v) || !re_v0_putc(v, '<'))
        return false;
    v->value = false;
    if (!re_v0_type(v) || !re_v0_putc(v, '>'))
        return false;
    v->value = false;
    return true;
}

// An inherent implementation prints as its self type in angle brackets and a trait
// implementation as "<type as trait>", which is the syntax Rust itself uses for a path
// that cannot be written any other way.
static bool path_trait(re_v0_t *v) {
    uint8_t tag = re_v0_peek(v);
    bool trait_value = false;
    v->pos++;
    if (tag == 'X' && !impl_path(v))
        return false;
    if (!re_v0_putc(v, '<'))
        return false;
    v->value = false;
    if (!re_v0_type(v) || !re_v0_puts(v, " as "))
        return false;
    v->value = false;
    if (!re_v0_path(v, &trait_value) || !re_v0_putc(v, '>'))
        return false;
    v->value = false;
    return true;
}

// A backref names a byte position: the number counts from the first byte after the prefix
// and encodes one less than the offset, the same convention the disambiguators use. The
// position is read as the path or type that is written there, and the cursor goes back to
// where it was, so what follows a backref follows the field and not the bytes it points at.
static bool path_backref(re_v0_t *v, bool *value) {
    uint64_t raw = 0;
    uint64_t target;
    size_t keep;
    v->pos++; // 'B'
    if (!re_v0_base62(v, &raw))
        return false;
    target = raw + v->base;
    keep = v->pos;
    if (target >= v->n) {
        v->bad = true;
        return false;
    }
    v->pos = (size_t)target;
    if (!re_v0_path(v, value)) {
        v->pos = keep;
        return false;
    }
    v->pos = keep;
    return true;
}

// A path: the names of an entity, with the parts that have no name of their own (impls)
// written the way Rust writes them. A tag outside this set is refused, because the
// alternative is printing a guess.
bool re_v0_path(re_v0_t *v, bool *value) {
    bool ok = false;
    if (v->bad || v->depth >= RE_V0_MAX_DEPTH) {
        v->bad = true;
        return false;
    }
    v->depth++;
    *value = false;
    switch (re_v0_peek(v)) {
        case 'C':
            ok = path_crate(v);
            *value = true;
            break;
        case 'N':
            ok = path_nested(v);
            *value = v->value;
            break;
        case 'M':
            ok = path_inherent(v);
            break;
        case 'X':
        case 'Y':
            ok = path_trait(v);
            break;
        case 'I':
            ok = re_v0_generic_args(v);
            break;
        case 'B':
            ok = path_backref(v, value);
            break;
        default:
            v->bad = true;
            break;
    }
    v->depth--;
    return ok && !v->bad;
}

// The v0 symbol: "_R", an unused version number, the path, and the parts that say where
// the entity was instantiated rather than what it is called.
bool re_v0_symbol(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    re_v0_t v;
    uint64_t version = 0;
    bool value = false;
    char *text;
    if (n < 4u || sym[0] != '_' || sym[1] != 'R')
        return false;
    v.p = (const uint8_t *)sym;
    v.n = n;
    v.pos = 2u;
    v.base = 3u;
    v.value = false;
    v.bad = false;
    v.skip = false;
    v.depth = 0;
    re_strbuf_init(&v.out, a);
    if (sym[2] >= '0' && sym[2] <= '9' && !re_v0_decimal(&v, &version))
        return false;
    if (!re_v0_path(&v, &value) || v.bad || v.out.len == 0)
        return false;
    text = re_strbuf_detach(&v.out);
    if (!text)
        return false;
    *out = re_str(text);
    return true;
}
