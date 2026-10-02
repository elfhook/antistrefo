// re_flirt.c - byte pattern library matching over the start of a function.
// Module: feature (C11).
// Owns: the comparison, the built in idioms, and the signature file reader.
// Depends: re_flirt.h. Patterns are compared literally, one byte at a time, and a
//           pattern that runs off the end of the code is a miss rather than a
//           partial hit.
#include "features/lib/re_flirt.h"

#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_strbuf.h"

#define RE_SIG_MAX 64

// A hex pair, or '?' for a byte the pattern does not care about.
static int sig_byte(char hi, char lo) {
    int h;
    int l;
    if (hi == '?' && lo == '?')
        return -1;
    h = re_hex_val(hi);
    l = re_hex_val(lo);
    if (h < 0 || l < 0)
        return -2; // malformed, which is a miss rather than a silent wildcard
    return (h << 4) | l;
}

bool re_sig_match(const re_code_t *c, uint64_t va, const re_sig_t *sig) {
    re_span_t b;
    size_t i = 0;
    size_t n = (size_t)sig->pattern.n / 2u;
    // Slack is how many trailing bytes the pattern makes no claim about. The field
    // existed and the matcher never looked at it, so a signature written with slack
    // either matched too little or, if slack were ever honoured elsewhere, would
    // claim a weaker match than it reports.
    size_t cmp = (size_t)sig->slack < n ? n - (size_t)sig->slack : 0u;
    if (cmp == 0 || cmp > RE_SIG_MAX)
        return false;
    if (!re_code_at(c, va, &b) || b.n < cmp)
        return false;
    while (i < cmp) {
        int want = sig_byte(sig->pattern.p[i * 2], sig->pattern.p[i * 2 + 1]);
        if (want == -2)
            return false;
        if (want >= 0 && b.p[i] != (uint8_t)want)
            return false;
        i++;
    }
    return true;
}

// Structural idioms the compiler emits on every x64 build. These are named for
// what they are, not for a library they might come from, because a pattern that
// says "msvc" and matches the security cookie check is a true statement.
static const char *const kBuiltIn[] = {
    // mov rax, [rip+__security_cookie]; sub rax, rbp; xor ebp, ebp
    "gs_cookie_init:msvc:488b05????????4883c8????33c5",
    // mov rcx, [rip+__security_cookie]; xor eax, eax
    "gs_cookie_read:msvc:488b0d????????33c0",
    // lea r11, [rip+disp] ; test r11, r11 ; je ...  the guard dispatch prologue
    "guard_dispatch_icall:msvc:4c8d1d????????4985ff7405",
};

// Split one line into its three fields, copying each into the arena. The copy is
// not optional: a line read out of a mapped file points into that mapping, and the
// mapping is released as soon as the file is closed, which would leave every loaded
// pattern pointing at unmapped memory. Returns false for a comment, a blank line,
// or a line without both separators, so a malformed entry is skipped rather than
// half loaded.
// The documented line puts a space either side of each colon, so every field is
// trimmed. Without this the pattern arrives as " 488bc453": the leading space is not
// a hex pair, sig_byte calls it malformed, and every signature in a perfectly valid
// file loads, is counted in the output, and matches nothing at all.
static re_str_t field(re_arena_t *a, const char *p, size_t n) {
    re_str_t s = re_strn(p, n);
    s = re_str_trim(s);
    return re_strn(re_arena_strndup(a, s.p, s.n), s.n);
}

static bool split_line(re_arena_t *a, re_str_t line, re_sig_t *out) {
    re_str_t t = re_str_trim(line);
    long sep1 = re_str_find_cstr(t, ":", 0);
    long sep2;
    if (t.n == 0 || t.p[0] == '#' || sep1 < 0)
        return false;
    sep2 = re_str_find_cstr(t, ":", (size_t)sep1 + 1u);
    if (sep2 < 0)
        return false;
    // An optional fourth field is how many trailing bytes are allowed to differ,
    // which is what lets one pattern cover a prologue ending in a stack adjustment of
    // a size the caller does not know. It was documented and never read.
    long sep3 = re_str_find_cstr(t, ":", (size_t)sep2 + 1u);
    size_t pend = sep3 < 0 ? t.n : (size_t)sep3;
    out->name = field(a, t.p, (size_t)sep1);
    out->module = field(a, t.p + sep1 + 1, (size_t)(sep2 - sep1 - 1));
    out->pattern = field(a, t.p + sep2 + 1, pend - (size_t)sep2 - 1u);
    out->slack = 0;
    if (out->name.n == 0)
        return false;
    // Refuse a pattern that could never match. Counting it would report a signature
    // that cannot do anything, which is how a file that does nothing looks loaded.
    if (out->pattern.n < 2u || (out->pattern.n & 1u) != 0u)
        return false;
    for (size_t i = 0; i < out->pattern.n; i += 2u) {
        if (sig_byte(out->pattern.p[i], out->pattern.p[i + 1]) == -2)
            return false;
    }
    if (sep3 >= 0) {
        re_str_t sv = field(a, t.p + sep3 + 1, t.n - (size_t)sep3 - 1u);
        if (sv.n == 0 || sv.n > 3u)
            return false;
        unsigned v = 0;
        for (size_t i = 0; i < sv.n; i++) {
            if (sv.p[i] < '0' || sv.p[i] > '9')
                return false;
            v = v * 10u + (unsigned)(sv.p[i] - '0');
        }
        if (v > out->pattern.n / 2u)
            return false; // more slack than there are bytes to skip is meaningless
        out->slack = (uint8_t)v;
    }
    return true;
}

size_t re_flirt_builtin(re_arena_t *a, re_vec_t *out) {
    re_vec_clear(out);
    for (size_t i = 0; i < sizeof(kBuiltIn) / sizeof(kBuiltIn[0]); i++) {
        re_sig_t s;
        if (split_line(a, re_str(kBuiltIn[i]), &s))
            RE_VEC_PUSH(out, a, s);
    }
    return RE_VEC_LEN(out);
}

// The line containing a byte, without its terminator. Both LF and CRLF are
// accepted, and a file with no final newline still yields its last line.
static re_str_t line_at(re_span_t f, uint64_t off) {
    uint64_t end = off;
    while (end < f.n && f.p[end] != '\n' && f.p[end] != '\r')
        end++;
    return re_strn((const char *)f.p + off, (size_t)(end - off));
}

// Appends rather than replacing. The caller loads the built in idioms first and then
// a file, and clearing here threw the idioms away: asking for a signature file
// silently cost the three built in patterns, which is the kind of loss that looks
// like the file having no effect rather than like a bug.
size_t re_flirt_load(re_arena_t *a, const char *path, re_vec_t *out) {
    re_file_t f;
    uint64_t off = 0;
    size_t added = 0;
    if (re_file_open(path, a, &f) != RE_OK)
        return 0;
    while (off < f.whole.n) {
        re_str_t line = line_at(f.whole, off);
        re_sig_t s;
        if (split_line(a, line, &s))
            added += RE_VEC_PUSH(out, a, s) ? 1u : 0u;
        off += line.n;
        // Step over the terminator, treating CRLF as one break.
        if (off < f.whole.n && f.whole.p[off] == '\r')
            off++;
        if (off < f.whole.n && f.whole.p[off] == '\n')
            off++;
    }
    re_file_close(&f);
    return added;
}

bool re_flirt_name(const re_code_t *c, const re_func_t *f, const re_vec_t *sigs, re_str_t *name,
                   re_str_t *module) {
    for (size_t i = 0; i < RE_VEC_LEN(sigs); i++) {
        const re_sig_t *s = RE_VEC_PTR(sigs, re_sig_t, i);
        if (!re_sig_match(c, f->va, s))
            continue;
        *name = s->name;
        *module = s->module;
        return true;
    }
    return false;
}
