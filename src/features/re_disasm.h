// re_disasm.h - the disassembler contract. One vtable, many architectures.
// Module: feature (C11).
// Owns: the decoded instruction record and the vtable every backend implements.
// Depends: re_ir and re_buf. No Capstone type may appear in this header.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_ir.h"
#include "utils/re_buf.h"
#include "utils/re_str.h"
#include "utils/re_strbuf.h"

#define RE_MAX_INSN_LEN 16

typedef struct {
    uint64_t addr;
    uint8_t size;
    // The opcode identity, map in the high byte and opcode in the low. Widened
    // from a single byte in task 3, when the two and three byte maps arrived.
    uint16_t insn_id;
    uint8_t op_count;
    bool is_branch;
    bool is_call;
    bool is_return;
    bool is_conditional; // branch that falls through as well as jumping
    bool rip_rel;        // the memory operand is RIP relative
    bool has_target;     // target is meaningful
    bool has_modrm;
    uint8_t modrm;
    uint8_t opsize;  // operand size in bytes: 1, 2, 4 or 8
    uint8_t rex;     // extension prefix, 0 when absent
    int64_t imm;     // immediate value, or the relative offset of a branch
    uint64_t target; // resolved branch or call destination
    uint8_t ops[4];  // architecture specific operand encodings
    re_str_t text;   // owned by the caller's arena, may be NULL
} re_insn_t;

typedef struct re_disasm {
    void *ctx;
    const char *arch_name;
    uint32_t mode; // 16, 32 or 64 bit address width
    // Decode exactly one instruction at addr. Returns false on a decode failure,
    // an invalid byte, or running off the end of code. Never guesses.
    bool (*decode)(void *ctx, uint64_t addr, re_span_t code, re_insn_t *out);
    // Lower one decoded instruction into the IR. Returns ops written, 0 when the
    // instruction is not modelled, which is not an error.
    size_t (*lower)(void *ctx, const re_insn_t *insn, re_ir_func_t *f, re_arena_t *a);
    // Register name for display and for the emitter's variable naming.
    const char *(*reg_name)(void *ctx, unsigned reg);
    // Register width in bytes, for the emitter's type inference.
    unsigned (*reg_size)(void *ctx, unsigned reg);
    // True when this address looks like the start of a function.
    bool (*is_prologue)(void *ctx, uint64_t addr, re_span_t code);
    const re_trfunc_t *(*trfunc)(void *ctx, uint8_t insn_id);
    // Render one instruction as text into the caller's buffer. Text is a
    // presentation concern, so it sits behind the vtable and never in the IR.
    void (*render)(void *ctx, const re_insn_t *insn, re_arena_t *a, re_strbuf_t *out);
} re_disasm_t;

// Backends are registered by name so the CLI never links an architecture it did
// not ask for, and RE_ENABLE_DISASM=OFF drops the whole table.
const re_disasm_t *re_disasm_find(const char *arch_name);
size_t re_disasm_arch_count(void);
const char *re_disasm_arch_name(size_t index);
#ifdef __cplusplus
}
#endif
