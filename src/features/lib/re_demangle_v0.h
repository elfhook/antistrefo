// re_demangle_v0.h - the cursor and the rules shared by the two halves of the v0 reader.
// Module: feature (C11, private).
// Owns: the cursor over a mangled symbol, and the pieces both halves read with it.
// Depends: re_demangle.h, re_strbuf. Private to the demangler: this is the state shared
//           between two files that were one until the reader outgrew a single file.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_arena.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

// How deep the reader will recurse. Every rule calls another on the same input, and an
// unbounded recursion on input from a file is how a reader becomes a stack overflow. A
// real symbol nests a handful of levels.
#define RE_V0_MAX_DEPTH 48
// The longest rendering accepted. A v0 name can be long, and unbounded is not a length.
#define RE_V0_MAX_OUT 4096

// The cursor. One pass over the mangled bytes; a backref moves it back to a previous
// position and restores it afterwards, which is what makes a backref a reference to a
// byte position rather than to a parsed value.
typedef struct re_v0_s {
    const uint8_t *p;
    size_t n;
    size_t pos;
    size_t base; // the origin backref offsets are counted from
    re_strbuf_t out;
    bool value; // the last segment rendered names a value, which decides "::<"
    bool bad;   // a construct outside this reader's subset was met
    bool skip;  // parsing something that is read but not shown
    unsigned depth;
} re_v0_t;

static inline uint8_t re_v0_peek(const re_v0_t *v) {
    return v->pos < v->n ? v->p[v->pos] : 0u;
}

static inline bool re_v0_eat(re_v0_t *v, uint8_t c) {
    if (re_v0_peek(v) != c)
        return false;
    v->pos++;
    return true;
}

bool re_v0_putc(re_v0_t *v, char c);
bool re_v0_puts(re_v0_t *v, const char *s);
bool re_v0_putn(re_v0_t *v, const uint8_t *p, size_t n);
bool re_v0_put_u64(re_v0_t *v, uint64_t x);
bool re_v0_base62(re_v0_t *v, uint64_t *out);
bool re_v0_decimal(re_v0_t *v, uint64_t *out);
bool re_v0_disamb(re_v0_t *v, uint64_t *out);
bool re_v0_ident(re_v0_t *v, uint64_t *dis, re_str_t *name);
bool re_v0_lifetime(re_v0_t *v, uint64_t *out);
bool re_v0_lifetime_print(re_v0_t *v, uint64_t idx);
bool re_v0_type(re_v0_t *v);
bool re_v0_const(re_v0_t *v);
bool re_v0_generic_args(re_v0_t *v);
bool re_v0_ref_type(re_v0_t *v, const char *prefix, bool lifetime_optional);
bool re_v0_path(re_v0_t *v, bool *value);

// Read a v0 symbol ("_R...") into out. False when the symbol is not one, or when it uses
// a construct this reader does not implement: a name it cannot account for is refused
// rather than approximated.
bool re_v0_symbol(re_arena_t *a, const char *sym, size_t n, re_str_t *out);

#ifdef __cplusplus
}
#endif
