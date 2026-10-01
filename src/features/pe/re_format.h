// re_format.h - magic detection. Decides which parser owns a file, nothing else.
// Module: feature (C11).
// Owns: the format enum and detection by magic bytes.
// Depends: re_buf and re_err. No globals beyond the name table, no I/O.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/mem/re_buf.h"
#include "utils/sys/re_err.h"

typedef enum {
    RE_FMT_UNKNOWN = 0,
    RE_FMT_PE,
    RE_FMT_ELF,
    RE_FMT_MACHO,
    RE_FMT_MACHO_FAT,
    RE_FMT_DOS,
    RE_FMT_NE,
    RE_FMT_LE,
    RE_FMT_WASM,
} re_format_t;

// Detects by magic only. A MZ file is reported as RE_FMT_PE only once the PE
// signature is confirmed, so a plain DOS stub does not get a PE parser.
re_format_t re_format_detect(re_span_t img);

const char *re_format_name(re_format_t f);

// Architecture hint from the format itself, before any section is read.
const char *re_format_arch_hint(re_span_t img, re_format_t f);

// True when the format has an addressable image base, which triage reports.
bool re_format_has_image_base(re_format_t f);
#ifdef __cplusplus
}
#endif
