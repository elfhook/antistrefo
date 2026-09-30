// re_dc_print.h - the printing layer of the decompiler: names, values, statements.
// Module: feature (C11).
// Owns: the emitter's mutable state and everything that renders a varnode.
// Depends: re_ir, re_strbuf, re_dc_walk, re_stack, re_xref, re_disasm.
//       reasons: this file changes when a new space or operator appears, and that
//       one changes when a new op kind appears.
// Depends: re_ir for the varnode and op kinds, re_strbuf for the output.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_dc_walk.h"
#include "features/re_disasm.h"
#include "features/re_ir.h"
#include "features/re_stack.h"
#include "features/re_xref.h"
#include "utils/re_strbuf.h"

#define RE_DC_REGS 32  // x86-64 general purpose registers, indexed by re_varnode_t.offset
#define RE_DC_TEXT 48  // width of a rendered operand, which is a short name or a literal
#define RE_DC_VARS 512 // temporaries per function, matching the IR's own bound

#define RE_DC_REGS 32  // x86-64 general purpose registers, indexed by re_varnode_t.offset
#define RE_DC_TEXT 48  // width of a rendered operand, which is a short name or a literal
#define RE_DC_VARS 512 // temporaries per function, matching the IR's own bound

typedef struct {
    re_strbuf_t *o;
    re_arena_t *a;
    const re_xrefset_t *xrefs; // consulted only to name a call target
    uint64_t insn_addr;        // the instruction being lowered, so a ref can be found
    re_str_t reg[RE_DC_REGS];  // the name currently holding each register
    re_str_t uniq[RE_DC_VARS]; // the name of each temporary, by the IR's unique id
    int64_t cval[RE_DC_VARS];  // the value of each constant, by the same id
    bool caddr[RE_DC_VARS];    // and whether that constant is an address, not a number
    bool touched[RE_DC_REGS];  // registers written since the last call, the argument set
    const re_stack_t *st;      // for naming locals and for the call arguments
    bool have_cmp;             // a comparison is waiting for a branch to use
    uint32_t cmp_cc;           // and the condition that comparison computed
    char cmp_l[RE_DC_TEXT];
    char cmp_r[RE_DC_TEXT];
    char lname[RE_DC_TEXT];
    uint32_t next_tmp;
    size_t n_stmts;
    size_t n_unknown;
    const re_disasm_t *dis;
} re_dc_emit_t;

// Format into a caller supplied buffer, for the few places that need a fragment
// before it becomes a statement. The statement writer takes its format directly, so
// this exists only for composing one.
void re_dc_fmt(char *dst, size_t cap, const char *fmt, ...);

// The printing layer's interface. Every one of these writes through the emitter, so
// they take it rather than reaching for a global, and each returns something the
// caller uses in the same statement.
re_str_t re_dc_mint(re_dc_emit_t *e, const char *prefix, uint32_t n);
const char *re_dc_val(re_dc_emit_t *e, re_varnode_t vn, char *scratch);
const char *re_dc_local(re_dc_emit_t *e, int16_t disp);
const char *re_dc_type(uint16_t size);
const char *re_dc_binop(re_op_kind_t k);
const char *re_dc_ccop(unsigned cc);
void re_dc_bind(re_dc_emit_t *e, re_varnode_t vn, re_str_t name);
void re_dc_stmt(re_dc_emit_t *e, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
