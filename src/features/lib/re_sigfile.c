// re_sigfile.c - the IDA .pat reader, and the reader a path's suffix selects.
// Module: feature (C11).
// Owns: the entry framing, the header fields, and the pattern translation.
// Depends: re_sigfile.h. A .pat pattern is translated into the native text and then
//           compiled by the one compiler, so an entry can never mean something the
//           native format cannot say and the matcher stays the only place that decides.
#include "features/lib/re_sigfile.h"

#include <string.h>

#include "utils/mem/re_buf.h"
#include "utils/sys/re_err.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

#define PAT_ENTRY_DASHES 8u // a line of these separates entries
#define PAT_BODY_DASHES 3u  // and this separates the pattern from the tail bytes

// A line cursor over the whole file. Both LF and CRLF are accepted, and a file with no
// final newline still yields its last line.
typedef struct {
    re_span_t body;
    uint64_t off;
} pat_lines_t;

static bool pat_line(pat_lines_t *ls, re_str_t *out) {
    uint64_t end = ls->off;
    if (ls->off >= ls->body.n)
        return false;
    while (end < ls->body.n && ls->body.p[end] != '\n' && ls->body.p[end] != '\r')
        end++;
    *out = re_strn((const char *)ls->body.p + ls->off, (size_t)(end - ls->off));
    while (end < ls->body.n && (ls->body.p[end] == '\r' || ls->body.p[end] == '\n'))
        end++;
    ls->off = end;
    return true;
}

// True when the line is nothing but dashes, at least n of them.
static bool pat_rule(re_str_t line, size_t n) {
    re_str_t t = re_str_trim(line);
    if (t.n < n)
        return false;
    for (size_t i = 0; i < t.n; i++) {
        if (t.p[i] != '-')
            return false;
    }
    return true;
}

// The next whitespace separated field, advancing i, or false at the end of the line.
static bool pat_field(re_str_t line, size_t *i, re_str_t *out) {
    size_t start = *i;
    while (start < line.n && (line.p[start] == ' ' || line.p[start] == '\t'))
        start++;
    if (start >= line.n)
        return false;
    *i = start;
    while (*i < line.n && line.p[*i] != ' ' && line.p[*i] != '\t')
        (*i)++;
    *out = re_strn(line.p + start, *i - start);
    return true;
}

static bool pat_hex_field(re_str_t f, size_t max_digits, uint32_t *out) {
    uint32_t v = 0;
    if (f.n == 0 || f.n > max_digits)
        return false;
    for (size_t i = 0; i < f.n; i++) {
        int d = re_hex_val(f.p[i]);
        if (d < 0)
            return false;
        v = (v << 4) | (uint32_t)d;
    }
    *out = v;
    return true;
}

// The length field is checked for its shape and not for its value: what it counts is
// stated differently by different tools, and a check against a guess would refuse
// valid entries while looking like a real check. The width is five rather than three
// because the field is written zero padded to four, which is the form a real file
// uses; a three digit limit refused every entry of a perfectly valid one.
static bool pat_digits_field(re_str_t f, size_t max_digits) {
    if (f.n == 0 || f.n > max_digits)
        return false;
    for (size_t i = 0; i < f.n; i++) {
        if (f.p[i] < '0' || f.p[i] > '9')
            return false;
    }
    return true;
}

// <crc16> <length> <name> and then the reference names, which this reader reads past.
// The shape is what makes a line a header: a line that does not fit it is not a header,
// so it can never become a signature whose name is a fragment of something else.
static bool pat_header(re_arena_t *a, re_str_t line, re_str_t *name, uint32_t *crc, bool *has_crc) {
    size_t i = 0;
    re_str_t f;
    if (!pat_field(line, &i, &f) || !pat_hex_field(f, 4, crc))
        return false;
    *has_crc = true;
    if (!pat_field(line, &i, &f) || !pat_digits_field(f, 5))
        return false;
    if (!pat_field(line, &i, &f) || f.n == 0)
        return false;
    *name = re_strn(re_arena_strndup(a, f.p, f.n), f.n);
    return true;
}

// The wildcard character, in either spelling. The dialect writes it as '.', and a
// reader who has used the native format writes '?'; both mean that half of the byte is
// not part of the claim, and refusing either would refuse files a reader can see to be
// correct.
static bool pat_wild(char c) {
    return c == '.' || c == '?';
}

// One two character group, rewritten in the native spelling. A group of two wildcards
// is a byte the pattern says nothing about, and one wildcard beside a hex digit fixes
// the other half: both are what the native '?' already means, so this rewrites and
// decides nothing.
static bool pat_group(char hi, char lo, char *out_hi, char *out_lo) {
    bool h = !pat_wild(hi) && re_hex_val(hi) >= 0;
    bool l = !pat_wild(lo) && re_hex_val(lo) >= 0;
    if (pat_wild(hi) && pat_wild(lo)) {
        *out_hi = '?';
        *out_lo = '?';
        return true;
    }
    if (h && pat_wild(lo)) {
        *out_hi = hi;
        *out_lo = '?';
        return true;
    }
    if (pat_wild(hi) && l) {
        *out_hi = '?';
        *out_lo = lo;
        return true;
    }
    if (h && l) {
        *out_hi = hi;
        *out_lo = lo;
        return true;
    }
    return false;
}

// Append one pattern line's groups. Spaces are ignored, because a group is two
// characters whether the file separates them or not.
static bool pat_pattern_line(re_strbuf_t *b, re_str_t line, size_t *bytes) {
    char prev = 0;
    bool have_prev = false;
    for (size_t i = 0; i < line.n; i++) {
        char c = line.p[i];
        char oh;
        char ol;
        if (c == ' ' || c == '\t')
            continue;
        if (!have_prev) {
            prev = c;
            have_prev = true;
            continue;
        }
        if (!pat_group(prev, c, &oh, &ol) || *bytes + 1u > RE_SIG_MAX)
            return false;
        re_strbuf_putc(b, oh);
        re_strbuf_putc(b, ol);
        (*bytes)++;
        have_prev = false;
    }
    // An odd number of characters leaves half a byte behind, which is a malformed line
    // rather than a byte the pattern does not care about.
    return !have_prev;
}

// One entry while it is being read. bad marks an entry whose framing was broken, so
// the rest of its lines are passed over rather than read as a second header.
typedef struct {
    re_strbuf_t pat;
    re_str_t name;
    uint32_t crc;
    bool have_crc;
    bool have_header;
    bool in_tail;
    bool bad;
    size_t nbytes;
} pat_entry_t;

static void pat_reset(pat_entry_t *e) {
    re_strbuf_clear(&e->pat);
    e->name = re_str("");
    e->crc = 0;
    e->have_crc = false;
    e->have_header = false;
    e->in_tail = false;
    e->bad = false;
    e->nbytes = 0;
}

// Compile the entry that just ended and push it, or report that it is not one. The
// module of every signature is the file's own name: a .pat does not state one per
// entry, and naming the module after the file that claimed it is the honest answer.
static bool pat_finish(re_arena_t *a, pat_entry_t *e, re_str_t module, re_vec_t *out) {
    re_sig_t s;
    if (e->bad || !e->have_header || e->nbytes == 0)
        return false;
    memset(&s, 0, sizeof(s));
    s.name = e->name;
    s.module = module;
    s.pattern = re_str(re_arena_strndup(a, e->pat.p ? e->pat.p : "", e->pat.len));
    s.crc = e->crc;
    s.has_crc = e->have_crc;
    return re_sig_compile(&s) && RE_VEC_PUSH(out, a, s);
}

// The file's own name, for the module of everything it defines.
static re_str_t pat_module(re_arena_t *a, const char *path) {
    const char *base = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    size_t n = 0;
    while (base[n])
        n++;
    return re_strn(re_arena_strndup(a, base, n), n);
}

// Close whatever entry is open, counting it once. A rejected entry is one that meant to
// be a signature and is not, which is different from the empty space between two
// separators: counting that as a refusal would report an error for a well formed file.
static void pat_close(re_arena_t *a, pat_entry_t *e, re_str_t module, re_vec_t *out,
                      re_flirt_load_stat_t *stat) {
    bool had_something = e->have_header || e->bad || e->nbytes > 0;
    if (pat_finish(a, e, module, out)) {
        if (stat)
            stat->loaded++;
    } else if (had_something && stat) {
        stat->rejected++;
    }
    pat_reset(e);
}

size_t re_sigfile_pat(re_arena_t *a, const char *path, re_vec_t *out, re_flirt_load_stat_t *stat) {
    re_file_t f;
    pat_lines_t ls;
    pat_entry_t e;
    re_str_t module;
    size_t before = out ? RE_VEC_LEN(out) : 0;
    if (stat) {
        stat->before = before;
        stat->loaded = 0;
        stat->rejected = 0;
        stat->skipped = 0;
    }
    if (!out || re_file_open(path, a, &f) != RE_OK)
        return 0;
    module = pat_module(a, path);
    re_strbuf_init(&e.pat, a);
    pat_reset(&e);
    ls.body = f.whole;
    ls.off = 0;
    for (re_str_t line;;) {
        bool more = pat_line(&ls, &line);
        re_str_t t = more ? re_str_trim(line) : re_str("");
        if (!more || pat_rule(t, PAT_ENTRY_DASHES)) {
            pat_close(a, &e, module, out, stat);
            if (!more)
                break;
            continue;
        }
        if (e.bad || e.in_tail) {
            // Past the pattern: a broken entry's remainder, or the tail bytes, which
            // this reader reads past rather than applies.
            if (stat)
                stat->skipped++;
            continue;
        }
        if (pat_rule(t, PAT_BODY_DASHES)) {
            e.in_tail = true;
            continue;
        }
        if (t.n == 0 || t.p[0] == '#') {
            if (stat)
                stat->skipped++;
            continue;
        }
        if (!e.have_header) {
            if (pat_header(a, line, &e.name, &e.crc, &e.have_crc))
                e.have_header = true;
            else
                e.bad = true;
            continue;
        }
        if (!pat_pattern_line(&e.pat, line, &e.nbytes))
            e.bad = true;
    }
    re_file_close(&f);
    before = RE_VEC_LEN(out) - before;
    if (stat)
        stat->loaded = before;
    return before;
}

size_t re_sigfile_load(re_arena_t *a, const char *path, re_vec_t *out, re_flirt_load_stat_t *stat) {
    if (re_str_ends_cstr(re_str(path), ".pat"))
        return re_sigfile_pat(a, path, out, stat);
    return re_flirt_load_ex(a, path, out, stat);
}
