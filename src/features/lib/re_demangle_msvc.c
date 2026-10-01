// re_demangle_msvc.c - Microsoft decorated form, the free functions only.
// Module: feature (C11).
// Owns: the MSVC name, calling convention and type code parser.
// Depends: re_demangle.h, re_str, re_strbuf, re_vec. Refuses anything it cannot
// read rather than guessing, so an unrecognised code keeps its raw symbol.
#include "features/lib/re_demangle.h"

#include <stdbool.h>
#include <stddef.h>

#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

// The parser state. Output goes through sink so a nested type can be rendered
// into a scratch buffer and measured before it is committed to out.
typedef struct {
    const char *p;
    const char *end;
    bool ok;
    re_strbuf_t out;
    re_strbuf_t *sink;
} mv_t;

static void mv_putc(mv_t *s, char c) {
    if (!re_strbuf_putc(s->sink, c))
        s->ok = false;
}

static void mv_putn(mv_t *s, const char *p, size_t n) {
    if (!re_strbuf_append(s->sink, p, n))
        s->ok = false;
}

static void mv_puts(mv_t *s, const char *text) {
    mv_putn(s, text, re_str(text).n);
}

static bool at(mv_t *s, char c) {
    return s->p < s->end && *s->p == c;
}

// True when the input starts with code, consuming it when it matches.
static bool take(mv_t *s, const char *code) {
    size_t n = re_str(code).n;
    if ((size_t)(s->end - s->p) < n)
        return false;
    for (size_t j = 0; j < n; j++) {
        if (s->p[j] != code[j])
            return false;
    }
    s->p += n;
    return true;
}

// Calling conventions that actually appear in user code. Anything not listed
// yields nothing rather than an invented name. The longer codes are tried
// first because the one letter YA is a prefix of all of them. YAX, IA and IZ
// are deliberately absent: they are indistinguishable from YA followed by a
// void return and an empty parameter list, and guessing loses the real one.
static const struct {
    const char *code;
    const char *name;
} kCallConv[] = {
    {"YAS", "__stdcall"}, {"YAU", "__thiscall"}, {"YAQ", "__vectorcall"},
    {"YAA", "__cdecl"},   {"YA", "__cdecl"},     {"QEAA", "__cdecl"},
    {"QEBA", "__cdecl"},  {"QEAI", "__cdecl"},   {"QEAX", "__cdecl"},
};

static const char *callconv(mv_t *s) {
    for (size_t i = 0; i < sizeof(kCallConv) / sizeof(kCallConv[0]); i++) {
        if (take(s, kCallConv[i].code))
            return kCallConv[i].name;
    }
    return NULL;
}

// The primitive type encodings, which are every code that is not a class, a
// pointer or void. Kept as a table so the mapping is auditable in one place.
static const struct {
    const char *code;
    const char *name;
} kPrim[] = {{"C", "signed char"},
             {"D", "char"},
             {"E", "unsigned char"},
             {"F", "short"},
             {"G", "unsigned short"},
             {"H", "int"},
             {"I", "unsigned int"},
             {"J", "long"},
             {"K", "unsigned long"},
             {"M", "float"},
             {"N", "double"},
             {"O", "long double"},
             {"_D", "int64"},
             {"_E", "unsigned __int64"},
             {"_N", "bool"},
             {"_W", "wchar_t"},
             {NULL, NULL}};

static bool mv_primitive(mv_t *s) {
    for (size_t i = 0; kPrim[i].name; i++) {
        if (!take(s, kPrim[i].code))
            continue;
        mv_puts(s, kPrim[i].name);
        return true;
    }
    return false;
}

// V class, U struct, T union, W enum. All four are written out by name.
static bool is_user_class(char c) {
    return c == 'V' || c == 'U' || c == 'T' || c == 'W';
}

static const char *class_label(char kind) {
    if (kind == 'U')
        return " struct";
    if (kind == 'T')
        return " union";
    if (kind == 'W')
        return " enum";
    return " class";
}

static void mv_class(mv_t *s);

// P introduces a pointer. The run of qualifier codes that follows carries the
// cv and alignment of the pointee; they are dropped, so the pointee is printed
// as a bare pointer rather than with qualifiers that may sit on the far side.
static void mv_pointer(mv_t *s) {
    while (s->p < s->end) {
        char c = *s->p;
        if (c != 'A' && c != 'B' && c != 'C' && c != 'D' && c != 'E' && c != 'F' && c != 'I')
            break;
        s->p++;
    }
    mv_puts(s, "*");
    if (s->ok)
        mv_class(s);
}

// ?AV, ?AU, ?AT and ?AW all carry the type by name. The name runs to the next
// @ and may itself be a nested chain, which is why this cannot be a table.
static void mv_user_class(mv_t *s, char kind) {
    const char *label = class_label(kind);
    if (s->p < s->end)
        s->p++;
    if (s->p < s->end)
        s->p++;
    while (s->ok && s->p < s->end && *s->p != '@') {
        char c = *s->p;
        if (c == '?') {
            s->p++;
            continue;
        }
        if (c == '@')
            break;
        mv_putc(s, c);
        s->p++;
    }
    while (s->ok && s->p < s->end && *s->p == '@')
        s->p++;
    mv_puts(s, label);
}

static void mv_class(mv_t *s) {
    if (at(s, '?') || at(s, '@')) {
        if (s->p + 1 < s->end && is_user_class(s->p[1])) {
            mv_user_class(s, s->p[1]);
            return;
        }
        s->ok = false;
        return;
    }
    if (at(s, 'X')) {
        s->p++;
        mv_puts(s, "void");
        return;
    }
    if (at(s, 'F')) {
        s->p++;
        if (s->p < s->end)
            s->p++;
        mv_puts(s, "void");
        if (s->p < s->end)
            s->p++;
        return;
    }
    if (at(s, 'D')) {
        s->p++;
        if (s->p < s->end && *s->p == 'P') {
            s->p++;
            mv_pointer(s);
            return;
        }
        if (s->p < s->end && *s->p == 'G') {
            s->p++;
            mv_puts(s, "unsigned long long");
            return;
        }
        s->ok = false;
        return;
    }
    if (!mv_primitive(s))
        s->ok = false;
}
static void mv_type(mv_t *s) {
    if (!s->ok || s->p >= s->end) {
        s->ok = false;
        return;
    }
    mv_class(s);
}

// Copy the undecorated function name, stopping at the scope separators.
static void mv_name(mv_t *s) {
    if (s->p < s->end && *s->p == '?') {
        s->p++;
        if (s->p < s->end && *s->p == '?')
            s->p++;
    }
    while (s->ok && s->p < s->end && *s->p != '@') {
        char c = *s->p;
        if (c == '?') {
            s->p++;
            continue;
        }
        if (c == '@')
            break;
        mv_putc(s, c);
        s->p++;
    }
    while (s->ok && s->p < s->end && *s->p == '@')
        s->p++;
}

// Collect every encoded type into a vec. The last one is the return value.
static void mv_collect_types(mv_t *s, re_arena_t *a, re_vec_t *types) {
    re_strbuf_t scratch;
    re_strbuf_init(&scratch, a);
    while (s->ok && s->p < s->end && *s->p != 'Z' && *s->p != '@') {
        re_strbuf_clear(&scratch);
        s->sink = &scratch;
        mv_type(s);
        s->sink = &s->out;
        if (!s->ok)
            return;
        re_str_t v =
            re_strn(re_arena_strndup(a, scratch.p ? scratch.p : "", scratch.len), scratch.len);
        RE_VEC_PUSH(types, a, v);
    }
}

// Render the parameter list. The last type is the return and is dropped; a lone
// void in the parameter position is the marker for an empty list.
static void mv_signature(mv_t *s, const re_vec_t *types) {
    size_t count = RE_VEC_LEN(types);
    size_t nparams = count ? count - 1u : 0u;
    if (nparams == 1) {
        const re_str_t *first = RE_VEC_PTR(types, re_str_t, 0);
        if (re_str_eq_cstr(*first, "void"))
            nparams = 0;
    }
    mv_puts(s, "(");
    for (size_t i = 0; i < nparams; i++) {
        if (i)
            mv_puts(s, ", ");
        const re_str_t *t = RE_VEC_PTR(types, re_str_t, i);
        mv_putn(s, t->p, t->n);
    }
    mv_puts(s, ")");
}

bool re_demangle_msvc(re_arena_t *a, const char *sym, size_t n, re_str_t *out) {
    mv_t s;
    s.p = sym;
    s.end = sym + n;
    s.ok = true;
    re_strbuf_init(&s.out, a);
    s.sink = &s.out;
    // A thunk stub or a vcall thunk carries a leading @?.
    if (s.p < s.end && *s.p == '@') {
        s.p += 2;
        if (s.p >= s.end)
            return false;
    }
    mv_name(&s);
    if (!s.ok || s.p >= s.end)
        return false;
    const char *cc = callconv(&s);
    if (!cc)
        return false;
    re_vec_t types;
    re_vec_init(&types, sizeof(re_str_t));
    mv_collect_types(&s, a, &types);
    if (!s.ok)
        return false;
    mv_signature(&s, &types);
    if (cc[0] != '\0' && !re_str_eq_cstr(re_str(cc), "__cdecl")) {
        // Only a non default convention is worth reporting, and it goes after
        // the signature so the name reads as a normal C declaration.
        mv_puts(&s, " ");
        mv_puts(&s, cc);
    }
    while (s.p < s.end && (*s.p == 'Z' || *s.p == '@'))
        s.p++;
    if (s.p != s.end)
        return false;
    char *text = re_strbuf_detach(&s.out);
    if (!text || re_str(text).n == 0)
        return false;
    *out = re_str(text);
    return true;
}
