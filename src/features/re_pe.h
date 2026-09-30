// re_pe.h - PE and COFF structure, parsed defensively into a flat arena record.
// Module: feature (C11).
// Owns: DOS and NT headers, sections, data directories, imports, exports, rva map.
// Depends: re_buf, re_vec, re_str, re_err. No globals, no I/O, no allocation.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils/re_arena.h"
#include "utils/re_buf.h"
#include "utils/re_entropy.h"
#include "utils/re_err.h"
#include "utils/re_str.h"
#include "utils/re_strbuf.h"
#include "utils/re_vec.h"

#define RE_PE_MAX_SECTIONS 128
#define RE_PE_MAX_DIRS 16
#define RE_PE_DLL_NAME_MAX 96
#define RE_PE_IMPORT_LIMIT 4096

typedef struct {
    char name[9];
    uint32_t vaddr;
    uint32_t vsize;
    uint32_t rsize;
    uint32_t rptr;
    uint32_t chars;
    double entropy;
} re_pe_section_t;

typedef struct {
    re_str_t dll;
    uint32_t first_sym; // index into re_pe_t::syms
    uint32_t n_syms;
    // RVA of this module's first IAT slot. Code reaches an import through
    // [rip+slot], so without this a call target cannot be named.
    uint32_t first_thunk;
} re_pe_imp_t;

typedef struct {
    uint32_t ordinal;
    uint32_t rva;
    re_str_t name;
} re_pe_exp_t;

typedef struct {
    bool valid;
    bool pe32plus;
    bool has_ascii;  // characteristics IMAGE_FILE_EXECUTABLE_IMAGE
    bool is_dll;     // characteristics IMAGE_FILE_DLL
    bool signed_hdr; // optional header directories[4] present
    uint16_t machine;
    uint16_t n_sec_field;
    uint16_t opt_size;
    uint16_t chars;
    uint16_t subsystem;
    uint16_t dll_chars;
    uint32_t timestamp;
    uint32_t entry_rva;
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t n_dirs;
    uint32_t dd_rva[RE_PE_MAX_DIRS];
    uint32_t dd_size[RE_PE_MAX_DIRS];
    re_pe_section_t sec[RE_PE_MAX_SECTIONS];
    uint16_t n_sec;
    re_vec_t imports; // re_pe_imp_t
    re_vec_t syms;    // re_str_t, flat, indexed by first_sym
    re_vec_t exports; // re_pe_exp_t
    re_err_t err;
} re_pe_t;

// Parse a mapped image. Never reads past the span and never trusts a count that
// came from the file, so a truncated or hostile image yields an error, not a crash.
re_err_code_t re_pe_parse(re_span_t img, re_arena_t *a, re_pe_t *out);

// Translate a relative virtual address to a file offset. Returns false for an
// address outside every section, which is normal for headers and for relocations.
bool re_pe_rva2off(const re_pe_t *pe, uint32_t rva, uint64_t *out);

// The reverse mapping, for turning a file offset back into a virtual address.
bool re_pe_off2rva(const re_pe_t *pe, uint64_t off, uint32_t *out);

const char *re_pe_machine_name(uint16_t machine);
const char *re_pe_subsystem_name(uint16_t subsystem);
const char *re_pe_section_flags(uint32_t chars, re_strbuf_t *out);

// Data directory indices we actually consult, so no caller hardcodes a number.
enum {
    RE_PE_DD_EXPORT = 0,
    RE_PE_DD_IMPORT = 1,
    RE_PE_DD_RESOURCE = 2,
    RE_PE_DD_SECURITY = 4,
    RE_PE_DD_DEBUG = 6,
    RE_PE_DD_TLS = 9,
    RE_PE_DD_IAT = 12,
};
#ifdef __cplusplus
}
#endif
