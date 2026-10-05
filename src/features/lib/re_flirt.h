// re_flirt.h - FLIRT style byte pattern library matching over function starts.
// Module: feature (C11).
// Owns: the pattern compiler, the matcher, the first byte index, and the loaders.
// Depends: re_code, re_func, re_arena, re_vec, re_str. A pattern either matches or it
//           does not; no pattern is ever applied loosely enough to "roughly" hit.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

// The longest pattern that can be compiled. Wider than the first implementation's 64
// because a real library pattern often runs past the prologue into the body, and
// truncating it there would name a function on weaker evidence than the file claims.
#define RE_SIG_MAX 256u

// What the compiler decided about one pattern byte. A wildcard, an exact byte and a
// byte that must differ cannot share one value plus one mask, so the kind is kept
// next to the value and the matcher switches on it.
#define RE_SIGK_ANY 0u   // ??  any byte
#define RE_SIGK_EXACT 1u // hh  exactly this byte
#define RE_SIGK_NOT 2u   // !hh any byte except this one
#define RE_SIGK_HI 3u    // h?  this high nibble, any low nibble
#define RE_SIGK_LO 4u    // ?h  any high nibble, this low nibble

typedef struct {
    re_str_t name;
    re_str_t module;
    re_str_t pattern; // the text this was compiled from, so a report can show it
    uint8_t slack;    // trailing bytes the pattern makes no claim about
    uint16_t n;       // bytes compared, 0 when the pattern was refused
    // A checksum carried in from a .pat header. Retained rather than enforced: the
    // IDA polynomial is not reproducible from its documentation, and checking with a
    // guessed one would reject valid signatures while looking like a real check.
    uint32_t crc;
    bool has_crc;
    uint8_t kind[RE_SIG_MAX];
    uint8_t want[RE_SIG_MAX];
} re_sig_t;

// Compile pattern text into a signature, filling n, kind and want. The text is bytes:
//   hh exact, ?? any, h? and ?h one nibble fixed, !hh any byte but this one, @ four
//   bytes of a relative displacement, and spaces between tokens for readability.
// Returns false, leaving n at 0, for a malformed token, for a pattern longer than
// RE_SIG_MAX, and for slack that covers the whole pattern (such a pattern can never
// match, so counting it would report coverage that cannot fire). A refused pattern
// never degrades into a wildcard, which is the failure that looks like coverage.
bool re_sig_compile(re_sig_t *sig);

// True when the function's opening bytes match. The first n bytes less slack are
// compared; the rest of the function is left to the caller. An uncompiled signature
// (n at 0) matches nothing.
bool re_sig_match(const re_code_t *c, uint64_t va, const re_sig_t *sig);

// The pattern set, grouped by first byte so a scan does not compare every signature at
// every function. Built once per image, which is the whole point: a bucket lookup per
// function instead of a walk over the entire database.
typedef struct {
    const re_sig_t *sigs;
    size_t n;
    const re_sig_t **order; // the same signatures, grouped by bucket
    size_t off[258];        // bucket b covers order[off[b] .. off[b + 1]); 256 is the rest
} re_sigdb_t;

// Index a compiled set. A signature whose first byte is exact sits in that byte's
// bucket; everything else (a wildcard, a negation, a nibble) sits in the last bucket,
// which every function consults, because only an exact first byte can be ruled out
// before reading the function. An empty set is valid and matches nothing.
void re_sigdb_build(re_arena_t *a, const re_vec_t *sigs, re_sigdb_t *out);

// Name a function from the strongest signature that matches. An exact first byte is a
// stronger claim than a wildcarded one, so the exact bucket is consulted first. False
// when nothing matches, and the caller must then leave the function unnamed.
bool re_sigdb_name(const re_sigdb_t *db, const re_code_t *c, const re_func_t *f, re_str_t *name,
                   re_str_t *module);

// The built in set: compiler idioms and library functions recovered from real binaries,
// each entry carrying the provenance that verified it. Naming a library function needs
// a pattern that was matched against real bytes; inventing one here would put confident
// wrong names into every report, which is worse than an unnamed function.
size_t re_flirt_builtin(re_arena_t *a, re_vec_t *out);

// What a load did, kept because "loaded nothing" and "refused everything" are different
// problems with different fixes, and one number cannot tell them apart.
typedef struct {
    size_t before;   // what the set already held, which is the built in set when a
                     // load starts from it. Counted here rather than by the reader,
                     // so a caller reporting a database size cannot double count.
    size_t loaded;   // signatures a file added that can match
    size_t rejected; // entries that looked like a signature and could not compile
    size_t skipped;  // blank lines and comments, which are not failures
} re_flirt_load_stat_t;

// Load a signature file. One signature per line in the native format:
//   name : module : pattern [: slack]
// with # starting a comment. Lines are appended, so the built in idioms survive asking
// for a file. A malformed line is refused and counted rather than half loaded, because
// a signature that cannot match anything looks exactly like coverage.
size_t re_flirt_load_ex(re_arena_t *a, const char *path, re_vec_t *out, re_flirt_load_stat_t *stat);

// The same load without the breakdown. A path that cannot be read loads nothing and is
// not an error to guess around; the stat form is how a caller reports which it was.
size_t re_flirt_load(re_arena_t *a, const char *path, re_vec_t *out);

// Name every function that has no name of its own, from an indexed set. An export
// name wins, because the image states it and a pattern only infers it, and a function
// that matches nothing is left unnamed rather than given a plausible label. Returns
// how many it named, and marks each one it did with RE_FUNC_FLIRT.
size_t re_flirt_name_all(const re_sigdb_t *db, re_code_t *code, re_fscan_t *scan);
#ifdef __cplusplus
}
#endif
