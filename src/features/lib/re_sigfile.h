// re_sigfile.h - signature files: the IDA .pat dialect, and the reader dispatcher.
// Module: feature (C11).
// Owns: translating a .pat pattern into the native one, and choosing a reader.
// Depends: re_flirt, re_arena, re_vec. The .pat reader translates rather than
//           matching, so what a pattern means is decided in exactly one place.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>

#include "features/lib/re_flirt.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

// Load a signature file, choosing the reader by suffix: a name ending in .pat is read
// as the IDA text dialect, anything else as the native format. Both answer with the
// same three counts, so a caller cannot tell them apart except by what they accepted.
size_t re_sigfile_load(re_arena_t *a, const char *path, re_vec_t *out, re_flirt_load_stat_t *stat);

// The .pat reader on its own, for a caller that already knows the dialect.
//
// The subset supported is the one the format's description states and no more: entries
// separated by a line of eight or more dashes, a header line of <crc16> <length>
// <name>, the pattern in hex with '..' for a whole byte and '.' for half of one, then a
// line of three dashes, then tail bytes. The crc16 and the length are read and not
// enforced, because the polynomial behind the checksum is not reproducible from its
// documentation and checking against a guessed one would reject valid signatures while
// looking like a real check. Tail bytes are parsed and not used, and the entry is
// counted so a reader can see how much of the file was not applied. Anything outside
// the subset is refused and counted rather than half applied, and the module of every
// signature is the file's own name, which is the only library name a .pat states.
size_t re_sigfile_pat(re_arena_t *a, const char *path, re_vec_t *out, re_flirt_load_stat_t *stat);
#ifdef __cplusplus
}
#endif
