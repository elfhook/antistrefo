// re_func.h - function discovery by recursive descent over decoded control flow.
// Module: feature (C11).
// Owns: seed selection, the walk, the per function record, and the edge list.
// Depends: re_code, re_disasm, re_vec. Refuses to report a function it did not walk.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_code.h"
#include "utils/re_arena.h"
#include "utils/re_str.h"
#include "utils/re_vec.h"

// What we know about how a function was found. These are reasons, not verdicts:
// a function found by a prologue sniff is weaker evidence than one reached from
// the entry point, and the difference is worth reporting rather than hiding.
#define RE_FUNC_ENTRY 0x0001u    // reachable from the PE entry point
#define RE_FUNC_EXPORT 0x0002u   // has an export directory entry
#define RE_FUNC_PROLOGUE 0x0004u // starts with a recognisable prologue
#define RE_FUNC_FLIRT 0x0008u    // matched a FLIRT signature
#define RE_FUNC_THUNK 0x0010u    // jumps or calls straight through
#define RE_FUNC_NORETURN 0x0020u // no return instruction on any path
#define RE_FUNC_OVERLAP 0x0040u  // overlaps a function found earlier
#define RE_FUNC_EXTERNAL 0x0080u // makes a call that leaves the code section
#define RE_FUNC_JTABLE 0x0100u   // ends in a jump table dispatch
#define RE_FUNC_RET 0x0200u      // a return was seen on at least one path

#define RE_FUNC_MAX_INSNS 4096u

typedef enum {
    RE_EDGE_NONE = 0,
    RE_EDGE_CALL,
    RE_EDGE_JUMP,
    RE_EDGE_COND,
    RE_EDGE_DATA,
} re_edge_kind_t;

typedef struct {
    uint64_t from;
    uint64_t to;
    uint8_t kind; // re_edge_kind_t
    bool has_to;
} re_edge_t;

typedef struct {
    uint64_t va;
    uint64_t dispatch; // first indirect branch, 0 when there is none
    uint32_t rva;
    uint32_t size;       // bytes from va to the highest address walked
    uint32_t frame_size; // stack bytes reserved, 0 when there is no frame
    uint32_t n_insns;
    uint32_t n_calls;
    uint32_t n_jumps;
    uint32_t flags;
    re_str_t name; // from exports or FLIRT, empty otherwise
} re_func_t;

typedef struct {
    re_vec_t funcs; // re_func_t
    re_vec_t edges; // re_edge_t, the raw control flow the walk saw
} re_fscan_t;

// Walk the image. Seeds the entry point and the export table, then follows calls
// and jumps, then looks for unmarked prologues so functions only reachable
// through a table are still found. Every record here was actually decoded.
void re_func_scan(re_code_t *c, re_arena_t *a, re_fscan_t *out);

void re_fscan_init(re_fscan_t *s);

// Index of the function containing va, or -1. Functions do not overlap in a
// well formed image, so a binary search over the sorted table is exact.
long re_func_index_of(const re_fscan_t *s, uint64_t va);

// The function at index, or NULL past the end.
const re_func_t *re_func_at(const re_fscan_t *s, size_t index);

// How many control flow edges leave this function.
size_t re_func_edge_count(const re_fscan_t *s, const re_func_t *f);
#ifdef __cplusplus
}
#endif
