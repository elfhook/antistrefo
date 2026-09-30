// re_util.h - aggregator that pulls in the whole utility surface in one include.
// Module: util (C11).
// Owns: nothing. Convenience only, and the list scripts/check.py diffs against.
// Depends: every other re_util header. Core features must include what they use.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
// Only src/cli and src/mcp include this. A core feature that includes the
// aggregator pays for every utility it does not use, which is exactly the kind
// of accidental coupling the layering rules exist to prevent.
#include "utils/re_arena.h"
#include "utils/re_bits.h"
#include "utils/re_buf.h"
#include "utils/re_crc.h"
#include "utils/re_entropy.h"
#include "utils/re_err.h"
#include "utils/re_fmt.h"
#include "utils/re_hash.h"
#include "utils/re_hex.h"
#include "utils/re_jr.h"
#include "utils/re_json.h"
#include "utils/re_log.h"
#include "utils/re_map.h"
#include "utils/re_path.h"
#include "utils/re_regex.h"
#include "utils/re_set.h"
#include "utils/re_sort.h"
#include "utils/re_str.h"
#include "utils/re_strbuf.h"
#include "utils/re_text.h"
#include "utils/re_time.h"
#include "utils/re_tui.h"
#include "utils/re_vec.h"
#ifdef __cplusplus
}
#endif
