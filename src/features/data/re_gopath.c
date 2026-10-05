// re_gopath.c - the Go function table, located and read out of a mapped image.
// Module: feature (C11).
// Owns: the magic search, the header field probe, and the row reader.
// Depends: re_gopath.h, re_buf. The header's fields are not assumed: the one that
//           points at the function table is the one whose rows hold together, and the
//           name table is the one the rows' names resolve in, so a layout this reader
//           has not seen is refused rather than misread.
#include "features/data/re_gopath.h"

#include <string.h>

#include "utils/mem/re_buf.h"

// The two magics this reader knows. The header that follows each one is the same run
// of counts and pointers, so the version is reported rather than branched on: Go moved
// the fields between releases without changing what they mean.
#define RE_GO_MAGIC_118 0xfffffff0u
#define RE_GO_MAGIC_120 0xfffffff1u

// Where the header's fields may start and end, as file offsets past the magic. Fields
// are probed across this window at pointer sized steps instead of being read at
// hardcoded offsets, because a wrong offset still reads a number, and a number that
// looks like an offset is exactly what this reader must not turn into a function list.
#define GO_FIELD_FIRST 16u
#define GO_FIELD_LAST 88u
// How many rows and how many names are checked while choosing a field. Enough that a
// coincidence cannot pass, few enough that the probe stays a probe rather than a scan.
#define GO_PROBE_ROWS 48u
#define GO_PROBE_NAMES 32u

typedef struct {
    uint64_t ft;   // file offset of the function table
    uint64_t name; // file offset of the name table
    uint32_t nfunc;
    uint32_t ptr_size;
    uint32_t version;
} go_head_t;

// What a candidate name table scored: records that named something readable out of it,
// and records sampled. Kept together because a bare count says nothing without the
// denominator it came from.
typedef struct {
    size_t named;
    size_t seen;
} go_score_t;

// A pointer sized field out of the image. False past the end rather than a short read,
// so a field that runs off the file is a rejected candidate and not a number.
static bool go_ptr(re_span_t img, uint64_t off, uint32_t ptr_size, uint64_t *out) {
    if (ptr_size == 4u) {
        uint32_t v = 0;
        if (!re_rd32(img, off, &v))
            return false;
        *out = v;
        return true;
    }
    return re_rd64(img, off, out);
}

// One table row: the entry offset and the offset of the function record. Both are
// thirty two bit wide in every version this reader knows.
static bool go_row(re_span_t img, uint64_t ft, uint32_t i, uint32_t *eoff, uint32_t *foff) {
    uint64_t at = ft + (uint64_t)i * 8u;
    return re_rd32(img, at, eoff) && re_rd32(img, at + 4u, foff);
}

// The entry offset a function record repeats at its own head. A table is only accepted
// when the two copies agree for every row, which is the check that stops a header field
// that merely looks like an offset from becoming a function list.
static bool go_rec_check(re_span_t img, uint64_t ft, uint32_t foff, uint32_t eoff) {
    uint32_t rec = 0;
    return re_rd32(img, ft + foff, &rec) && rec == eoff;
}

// The name a record points at, bounded twice: by the length cap and by the image. An
// offset of zero means the entry is unnamed - the runtime reads it that way, so a name
// read from there would be one the runtime does not believe either.
static bool go_name(re_span_t img, uint64_t base, uint32_t off, re_str_t *out) {
    uint64_t at = base + (uint64_t)off;
    size_t n = 0;
    if (off == 0 || at >= img.n)
        return false;
    while (n < RE_GO_NAME_MAX && at + n < img.n && img.p[at + n] != 0)
        n++;
    if (n == 0 || n >= RE_GO_NAME_MAX)
        return false;
    // A symbol name is printable text. Spaces appear inside Go names (a type equality
    // function for an interface is spelled with them) so they are allowed; control
    // bytes are what a wrong offset produces and they are not.
    for (size_t i = 0; i < n; i++) {
        if (img.p[at + i] < 0x20u || img.p[at + i] > 0x7eu)
            return false;
    }
    *out = re_strn((const char *)img.p + at, n);
    return true;
}

// Does this candidate look like the function table? Its rows must start at zero, be
// ordered by address, point at records that are ordered and that repeat their entry
// offset, and stay inside the image. The whole table is checked again as it is read.
static bool go_probe_rows(re_span_t img, uint64_t ft, uint32_t nfunc) {
    uint32_t rows = nfunc < GO_PROBE_ROWS ? nfunc : GO_PROBE_ROWS;
    uint32_t prev_e = 0;
    uint32_t prev_f = 0;
    for (uint32_t i = 0; i < rows; i++) {
        uint32_t e = 0;
        uint32_t f = 0;
        if (!go_row(img, ft, i, &e, &f) || !go_rec_check(img, ft, f, e))
            return false;
        if (e != 0 && i == 0)
            return false;
        if (i > 0 && (e < prev_e || f <= prev_f))
            return false;
        prev_e = e;
        prev_f = f;
    }
    return true;
}

// How many of the sampled records name something readable out of this candidate offset.
// This is the strongest statement available about a field: offset arithmetic can be
// wrong in a way that still yields a plausible number, and garbage offsets resolve
// nothing at all.
static go_score_t go_score_names(re_span_t img, uint64_t ft, uint32_t nfunc, uint64_t nb) {
    go_score_t sc;
    uint32_t step = nfunc > GO_PROBE_NAMES ? nfunc / GO_PROBE_NAMES : 1u;
    sc.named = 0;
    sc.seen = 0;
    for (uint32_t i = 0; i < nfunc && sc.seen < GO_PROBE_NAMES; i += step) {
        uint32_t e = 0;
        uint32_t f = 0;
        uint32_t no = 0;
        re_str_t nm;
        sc.seen++;
        if (!go_row(img, ft, i, &e, &f) || !re_rd32(img, ft + f + 4u, &no))
            continue;
        if (go_name(img, nb, no, &nm))
            sc.named++;
    }
    return sc;
}

// A name table is accepted only when most of the records sampled through it named
// something readable, and when there were enough of them to mean anything. A real table
// names nearly every entry it lists, so half is a low bar that a run of coincidences
// still cannot clear.
static bool go_score_ok(go_score_t sc) {
    return sc.named >= 4u && sc.named * 2u >= sc.seen;
}

// The name table starts with the marker the linker writes there, which is a fact about
// the table rather than a guess about offsets: when it is present the choice between two
// candidates is settled, and when a builder has left it out the score still decides.
static bool go_has_buildid(re_span_t img, uint64_t nb) {
    static const char kMark[] = "go:buildid";
    if (nb + sizeof(kMark) > img.n)
        return false;
    for (size_t i = 0; i + 1u < sizeof(kMark); i++) {
        if (img.p[nb + i] != (uint8_t)kMark[i])
            return false;
    }
    return true;
}

// Does the table list the image's entry point? A Go image's entry is one of its own
// functions, so an entry offset equal to the distance from the start of the code to the
// entry point has to be in the table. This is what fixes the origin those offsets are
// relative to: a table read from the wrong origin is worse than no table at all, because
// every name in it would sit on the wrong address, and no shift can satisfy this by
// accident. Rows are ordered by address, so the search is a bisection.
static bool go_has_entry(re_span_t img, const go_head_t *h, uint64_t text, uint64_t entry_va) {
    uint32_t lo = 0;
    uint32_t hi = h->nfunc;
    uint32_t want;
    if (entry_va < text || entry_va - text > 0xffffffffu)
        return false;
    want = (uint32_t)(entry_va - text);
    while (lo < hi) {
        uint32_t e = 0;
        uint32_t f = 0;
        uint32_t mid = lo + (hi - lo) / 2u;
        if (!go_row(img, h->ft, mid, &e, &f))
            return false;
        if (e == want)
            return true;
        if (e < want)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return false;
}

// The function table, then the name table. Candidates are walked in order and the first
// table whose rows hold together wins, because that test is decisive. Every candidate is
// then scored as a name table and the best score wins, because more than one field can
// be the right width and only one of them is the name table.
static bool go_choose_fields(re_span_t img, uint64_t at, go_head_t *h) {
    go_score_t best;
    bool best_mark = false;
    best.named = 0;
    best.seen = 0;
    h->ft = 0;
    h->name = 0;
    for (uint32_t off = GO_FIELD_FIRST; off <= GO_FIELD_LAST; off += h->ptr_size) {
        uint64_t cand = 0;
        if (!go_ptr(img, at + off, h->ptr_size, &cand) || cand == 0)
            continue;
        if (at + cand >= img.n || !go_probe_rows(img, at + cand, h->nfunc))
            continue;
        h->ft = at + cand;
        break;
    }
    if (h->ft == 0)
        return false;
    for (uint32_t off = GO_FIELD_FIRST; off <= GO_FIELD_LAST; off += h->ptr_size) {
        go_score_t sc;
        uint64_t cand = 0;
        bool mark;
        if (!go_ptr(img, at + off, h->ptr_size, &cand) || cand == 0 || at + cand >= img.n)
            continue;
        sc = go_score_names(img, h->ft, h->nfunc, at + cand);
        if (!go_score_ok(sc))
            continue;
        mark = go_has_buildid(img, at + cand);
        if (best_mark && !mark)
            continue;
        if (mark == best_mark && sc.named <= best.named)
            continue;
        best = sc;
        best_mark = mark;
        h->name = at + cand;
    }
    return h->name != 0;
}

// The fixed prologue of the header plus the field probe. The pointer size is read first
// because every field after the counts is that wide, so reading one at the wrong width
// produces a number that looks like an offset and is not.
static bool go_head(re_span_t img, uint64_t at, uint32_t magic, go_head_t *h) {
    uint32_t nfunc = 0;
    if (at + GO_FIELD_FIRST > img.n)
        return false;
    h->ptr_size = img.p[at + 7u];
    if (h->ptr_size != 4u && h->ptr_size != 8u)
        return false;
    if (img.p[at + 6u] != 1u && img.p[at + 6u] != 2u && img.p[at + 6u] != 4u)
        return false;
    if (!re_rd32(img, at + 8u, &nfunc) || nfunc == 0 || nfunc > RE_GO_NFUNC_MAX)
        return false;
    h->nfunc = nfunc;
    h->version = magic == RE_GO_MAGIC_120 ? 120u : 118u;
    return go_choose_fields(img, at, h);
}

// The first magic whose header holds together. Four bytes is a pattern that occurs in
// data by chance - a real image has one earlier in its own constants - so a candidate
// that fails the probe is stepped over rather than treated as the answer, and the scan
// continues past it. Candidates are taken at four byte alignment because the header is
// a naturally aligned structure and the linker keeps it that way; the first byte is
// compared before the word, so the search does not read four bytes at every offset of a
// file that can be hundreds of megabytes.
static bool go_find(re_span_t img, uint64_t *at, go_head_t *h) {
    for (uint64_t i = 0; i + 4u <= img.n; i += 4u) {
        uint32_t magic = 0;
        if (img.p[i] != 0xf0u && img.p[i] != 0xf1u)
            continue;
        if (!re_rd32(img, i, &magic))
            return false;
        if (magic != RE_GO_MAGIC_118 && magic != RE_GO_MAGIC_120)
            continue;
        if (!go_head(img, i, magic, h))
            continue;
        *at = i;
        return true;
    }
    return false;
}

// One entry of the table, pointed at its entry address and named if it has a name. A
// marker the linker inserts to bracket its own code is spelled with a "go:" prefix and
// is not a function, so it keeps its address and loses its name.
static bool go_read_row(re_span_t img, const go_head_t *h, uint32_t i, uint64_t text,
                        re_gosym_t *out) {
    uint32_t e = 0;
    uint32_t f = 0;
    uint32_t no = 0;
    if (!go_row(img, h->ft, i, &e, &f) || !re_rd32(img, h->ft + f + 4u, &no))
        return false;
    out->va = text + e;
    out->name = re_str("");
    if (go_name(img, h->name, no, &out->name) && out->name.n >= 3u && out->name.p[0] == 'g' &&
        out->name.p[1] == 'o' && out->name.p[2] == ':')
        out->name = re_str("");
    return true;
}

// Read the Go function table, appending its entries to out in table order.
//
// False when the image has no table, and also when what was found does not hold
// together: every entry offset appears twice and the two must agree, the entries must be
// ordered by address and land inside the code window the caller states, and at least
// half of them must carry a readable name. That last one is the check that matters,
// because a real table names nearly every entry it lists, so a run of coincidences
// cannot pass it and become a function list.
bool re_gopath_scan(re_span_t img, uint64_t text_start, uint64_t text_end, uint64_t entry_va,
                    re_arena_t *a, re_vec_t *out, re_goinfo_t *info) {
    go_head_t h;
    uint64_t at = 0;
    uint64_t prev = 0;
    size_t named = 0;
    size_t total = 0;
    bool truncated = false;
    if (info)
        memset(info, 0, sizeof(*info));
    if (!out || !a || !re_span_valid(img) || text_end <= text_start)
        return false;
    if (!go_find(img, &at, &h))
        return false;
    if (!go_has_entry(img, &h, text_start, entry_va))
        return false;
    for (uint32_t i = 0; i < h.nfunc; i++) {
        re_gosym_t s;
        if (!go_read_row(img, &h, i, text_start, &s))
            return false;
        // The table is ordered by address, because the runtime binary searches it, and
        // every entry is a function in the image's code. Either statement failing means
        // the header was misread, and a misread header is refused rather than reported
        // as a table with functions in odd places.
        if (s.va < text_start || s.va >= text_end || (total && s.va < prev))
            return false;
        prev = s.va;
        if (s.name.n)
            named++;
        total++;
        if (RE_VEC_LEN(out) >= RE_GO_MAX) {
            truncated = true;
            break;
        }
        RE_VEC_PUSH(out, a, s);
    }
    if (total == 0 || named * 2u < total)
        return false;
    if (info) {
        info->version = h.version;
        info->ptr_size = h.ptr_size;
        info->n_funcs = total;
        info->n_named = named;
        info->text_start = text_start;
        info->truncated = truncated;
    }
    return true;
}
