// re_stack.h - stack frame and calling convention inference for one function.
// Module: feature (C11).
// Owns: which registers arrive as arguments, the frame size, and the local slots.
// Depends: re_code, re_func, re_disasm. An argument count is only reported when
//         the registers that carry arguments were actually seen.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_code.h"
#include "features/re_func.h"
#include "utils/re_arena.h"
#include "utils/re_vec.h"

// The two conventions that matter for the architectures in scope. Everything else
// is reported as unknown rather than forced into one of them.
#define RE_CC_UNKNOWN 0u
#define RE_CC_MS64 1u // Windows: rcx, rdx, r8, r9
#define RE_CC_SYSV 2u // SysV: rdi, rsi, rdx, rcx, r8, r9

#define RE_CC_MAX_ARGS 6

typedef struct {
    uint8_t cc;                       // RE_CC_*
    uint32_t n_params;                // arguments inferred, 0 when nothing was seen
    uint32_t frame_size;              // stack bytes reserved, from the prologue
    uint32_t n_locals;                // distinct stack slots written below rbp or rsp
    uint32_t n_calls;                 // calls made, which clobber the volatile set
    uint8_t arg_regs[RE_CC_MAX_ARGS]; // the registers seen as arguments
    bool uses_frame_ptr;              // rbp is set up, so locals are rbp relative
    bool tail_call;                   // ends in a jump rather than a return
} re_stack_t;

// Analyse one function. The walk is linear from the entry, which is enough for a
// prologue and an argument scan, and it stops at the first address it cannot
// decode rather than guessing past the end.
void re_stack_analyze(re_code_t *c, const re_func_t *f, re_arena_t *a, re_stack_t *out);

// The convention's name, for display.
const char *re_cc_name(uint8_t cc);
#ifdef __cplusplus
}
#endif
