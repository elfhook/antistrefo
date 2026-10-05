// re_demangle_v0_types.c - the v0 reader's type side: types, consts, argument lists.
// Module: feature (C11).
// Owns: every production of the grammar that describes a type rather than a path.
// Depends: re_demangle_v0.h. A tag this half does not implement is refused, so a type it
//           prints is one it read rather than one it guessed at.
#include "features/lib/re_demangle_v0.h"

// The basic types, one letter each, in letter order so a lookup is an index. The gaps are
// letters the format does not use as a type, and a gap is refused rather than printed as
// something: a letter this table has no name for is not a name.
static const char *const kBasic[26] = {
    "i8",   "bool", "char", "f64", "str", "f32", NULL,  "u8", "isize", "usize", NULL,  "i32", "u32",
    "i128", "u128", "_",    NULL,  NULL,  "i16", "u16", "()", "...",   NULL,    "i64", "u64", "!",
};

// const-data: an optional sign, hex digits, and an underscore. The value is kept as text
// as well as a number because the number does not always fit, and printing a truncated
// one would be a wrong value rather than a refused one.
typedef struct {
    bool negative;
    bool any;
    uint64_t value;
    bool fits;
    const uint8_t *digits;
    size_t n_digits;
} v0_const_t;

static bool const_data(re_v0_t *v, v0_const_t *out) {
    uint64_t acc = 0;
    size_t start;
    out->negative = re_v0_eat(v, 'n');
    out->any = false;
    out->value = 0;
    out->fits = true;
    out->digits = v->p + v->pos;
    start = v->pos;
    while (v->pos < v->n && v->p[v->pos] != '_') {
        uint8_t c = v->p[v->pos];
        uint64_t d;
        if (c >= '0' && c <= '9')
            d = (uint64_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (uint64_t)(c - 'a') + 10u;
        else {
            v->bad = true;
            return false;
        }
        if (out->fits) {
            if (acc > (0xffffffffffffffffull - d) / 16u)
                out->fits = false;
            else
                acc = acc * 16u + d;
        }
        v->pos++;
        out->any = true;
    }
    if (!re_v0_eat(v, '_'))
        return false;
    out->n_digits = v->pos - 1u - start;
    out->value = acc;
    return true;
}

// A const prints as its value for the types whose value a reader can use, and as the
// digits the linker wrote for anything else. Printing nothing is not an option: an
// argument that silently disappears reads as an argument that is not there.
static bool const_print(re_v0_t *v, uint8_t type_tag, const v0_const_t *c) {
    if (!c->any)
        return re_v0_puts(v, "0");
    if (type_tag == (uint8_t)'b')
        return re_v0_puts(v, c->value == 0 ? "false" : "true");
    if (!c->fits || type_tag == 0 || c->n_digits == 0)
        return re_v0_putn(v, c->digits, c->n_digits);
    if (c->negative && !re_v0_putc(v, '-'))
        return false;
    return re_v0_put_u64(v, c->value);
}

// const: a type and its data, a placeholder, or a backref to an earlier one.
bool re_v0_const(re_v0_t *v) {
    uint64_t raw = 0;
    uint64_t target;
    size_t keep;
    uint8_t tag;
    v0_const_t c;
    if (re_v0_eat(v, 'p')) {
        v->value = false;
        return re_v0_putc(v, '_');
    }
    if (re_v0_peek(v) == 'B') {
        v->pos++;
        if (!re_v0_base62(v, &raw))
            return false;
        target = raw + v->base;
        keep = v->pos;
        if (target >= v->n) {
            v->bad = true;
            return false;
        }
        v->pos = (size_t)target;
        if (!re_v0_const(v)) {
            v->pos = keep;
            return false;
        }
        v->pos = keep;
        return true;
    }
    tag = re_v0_peek(v);
    if (!re_v0_type(v) || !const_data(v, &c))
        return false;
    return const_print(v, tag, &c);
}

// A reference or a pointer. The lifetime is not displayed for the erased case, which is
// what Rust prints for a reference whose lifetime does not matter.
bool re_v0_ref_type(re_v0_t *v, const char *prefix, bool lifetime_optional) {
    uint64_t idx = 0;
    bool has_lifetime = lifetime_optional && re_v0_peek(v) == 'L';
    if (has_lifetime && !re_v0_lifetime(v, &idx))
        return false;
    if (!re_v0_puts(v, prefix))
        return false;
    if (has_lifetime && idx != 0 && (!re_v0_lifetime_print(v, idx) || !re_v0_putc(v, ' ')))
        return false;
    v->value = false;
    return re_v0_type(v);
}

// A tuple: the fields in order, comma separated. An empty tuple is encoded as a basic type
// instead, so an empty list here is refused rather than printed as something.
static bool tuple_type(re_v0_t *v) {
    unsigned n = 0;
    if (!re_v0_putc(v, '('))
        return false;
    while (re_v0_peek(v) != 'E') {
        if (n && !re_v0_puts(v, ", "))
            return false;
        v->value = false;
        if (!re_v0_type(v))
            return false;
        n++;
    }
    v->pos++; // 'E'
    // A one-element tuple is a tuple only because of its trailing comma: the same text
    // without it is a parenthesized type, which in Rust is not a tuple at all.
    if (n == 1 && !re_v0_putc(v, ','))
        return false;
    return re_v0_putc(v, ')');
}

static bool array_type(re_v0_t *v, bool sized) {
    if (!re_v0_putc(v, '['))
        return false;
    v->value = false;
    if (!re_v0_type(v))
        return false;
    if (!sized)
        return re_v0_putc(v, ']');
    if (!re_v0_puts(v, "; ") || !re_v0_const(v))
        return false;
    return re_v0_putc(v, ']');
}

// A generic argument list. A value path separates its arguments with "::", a type path
// does not, because that is the difference between a call to a generic function and the
// name of a generic type.
bool re_v0_generic_args(re_v0_t *v) {
    bool value = false;
    unsigned n = 0;
    uint64_t idx = 0;
    v->pos++; // 'I'
    if (!re_v0_path(v, &value))
        return false;
    if (value && !re_v0_puts(v, "::"))
        return false;
    if (!re_v0_putc(v, '<'))
        return false;
    while (re_v0_peek(v) != 'E') {
        if (n && !re_v0_puts(v, ", "))
            return false;
        if (re_v0_peek(v) == 'L') {
            if (!re_v0_lifetime(v, &idx) || !re_v0_lifetime_print(v, idx))
                return false;
        } else if (re_v0_eat(v, 'K')) {
            if (!re_v0_const(v))
                return false;
        } else {
            v->value = false;
            if (!re_v0_type(v))
                return false;
        }
        n++;
    }
    v->pos++; // 'E'
    v->value = false;
    return re_v0_putc(v, '>');
}

// A type. Only the productions a symbol can carry into a name are read; a function type,
// a trait object, or a splatted type is refused, because printing one wrongly would name
// the wrong thing, and a refused symbol still shows what the linker wrote.
bool re_v0_type(re_v0_t *v) {
    uint8_t c;
    bool value = false;
    if (v->bad || v->depth >= RE_V0_MAX_DEPTH) {
        v->bad = true;
        return false;
    }
    c = re_v0_peek(v);
    if (c >= 'a' && c <= 'z') {
        const char *name = kBasic[(size_t)(c - 'a')];
        v->pos++;
        if (!name) {
            v->bad = true;
            return false;
        }
        return re_v0_puts(v, name);
    }
    if (c == 'A')
        return v->pos++, array_type(v, true);
    if (c == 'S')
        return v->pos++, array_type(v, false);
    if (c == 'T')
        return v->pos++, tuple_type(v);
    if (c == 'R')
        return v->pos++, re_v0_ref_type(v, "&", true);
    if (c == 'Q')
        return v->pos++, re_v0_ref_type(v, "&mut ", true);
    if (c == 'P')
        return v->pos++, re_v0_ref_type(v, "*const ", false);
    if (c == 'O')
        return v->pos++, re_v0_ref_type(v, "*mut ", false);
    if (!re_v0_path(v, &value))
        return false;
    v->value = false;
    return true;
}
