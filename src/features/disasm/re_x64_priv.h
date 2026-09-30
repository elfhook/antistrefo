// re_x64_priv.h - internal decoder types for x86-64. Private to src/features/disasm.
// Module: feature (C11).
// Owns: the decode result struct, the opcode classes, and the backend entry points.
// Depends: re_disasm.h. No other feature may include this; it is not a seam.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_disasm.h"

// What an opcode does to the instruction stream. The decoder only needs to know
// whether a ModRM follows and how wide the immediate is, so a class is the whole
// of the knowledge needed to walk to the next instruction.
typedef enum {
    XC_BAD = 0,   // not a valid 64-bit opcode, so the walk stops here
    XC_NONE,      // nothing follows
    XC_MODRM,     // ModRM only
    XC_MODRM_IB,  // ModRM then imm8
    XC_MODRM_IW,  // ModRM then imm16
    XC_MODRM_IZ,  // ModRM then imm16 or imm32, picked by the 0x66 prefix
    XC_MODRM_IZB, // ModRM then imm8, sign extended to the operand size
    XC_REL8,      // rel8
    XC_REL32,     // rel32, which is the only branch width 64-bit mode uses
    XC_IB,        // imm8
    XC_IW,        // imm16
    XC_IZ,        // imm16 or imm32, no ModRM
    XC_IBS,       // imm8 sign extended to 64 bits
    XC_IV,        // imm16, imm32, or imm64, the last only with REX.W
    XC_PTR,       // an 8 byte absolute address, no ModRM
    XC_IW_IB,     // imm16 then imm8, which only enter needs
    XC_MODRM_F6,  // ModRM, then imm8 only when reg selects TEST
    XC_MODRM_F7,  // ModRM, then imm16/32 only when reg selects TEST
    XC_3DNOW,     // 0F 0F, ModRM then a trailing imm8 selector
} x64_class_t;

// A decoded instruction, before it is projected onto the arch neutral re_insn_t.
typedef struct {
    uint16_t id;      // map in the high bits, opcode in the low
    uint8_t map;      // 0 one-byte, 1 for 0F, 2 for 0F38, 3 for 0F3A
    uint8_t opcode;   // the opcode byte itself, before the map is applied
    uint8_t cls;      // x64_class_t
    uint8_t modrm;    // 0 when the instruction has no ModRM
    bool has_modrm;   // separate from modrm, because a ModRM byte can be 0x00
    uint8_t rex;      // REX byte, 0 when absent
    uint8_t size;     // bytes consumed from the span
    uint8_t opsize;   // operand size in bytes: 2, 4 or 8
    uint8_t addrsize; // address size in bytes: 4 or 8
    bool rip_rel;     // the ModRM used RIP relative addressing
    bool vex;         // encoded with a VEX or EVEX prefix
    int64_t imm;      // immediate, or the relative offset for a branch
    int64_t disp;     // RIP relative displacement, signed
    uint64_t target;  // resolved branch or call destination
    uint64_t mem;     // effective address of a RIP relative operand
    bool has_target;
} x64_insn_t;

// The opcode id packs the map so one 16 bit value identifies any encoding.
#define X64_MAP_SHIFT 8
#define X64_ID(map, op) ((uint16_t)(((map) << X64_MAP_SHIFT) | (op)))
#define X64_ID_MAP(id) ((uint8_t)((id) >> X64_MAP_SHIFT))
#define X64_ID_OP(id) ((uint8_t)((id) & 0xFFu))

// Decode one instruction from the front of p. Returns false, and writes nothing
// usable, on a bad opcode or a truncated instruction. Never guesses a length.
bool x64_decode(const uint8_t *p, size_t n, uint64_t addr, x64_insn_t *out);

// Operand and register helpers, so re_x64_decode.c and re_x64_ops.c agree.
const char *x64_mnem(uint16_t id);
unsigned x64_reg_size(const x64_insn_t *in);
const char *x64_reg_name(unsigned reg, uint8_t opsize);
const char *x64_reg_name_ex(unsigned reg, uint8_t opsize, uint8_t rex);

// True when the three byte F3 0F 1E FA/FB endbr sequence starts at p. Modern
// x86-64 code opens nearly every function with one, so it must be recognized.
bool x64_is_endbr(const uint8_t *p, size_t n);

// The vtable, wired up in re_x64_ops.c.
extern const struct re_disasm re_disasm_x64;

// Text rendering, in re_x64_text.c, and the IR lowering, in re_x64_lower.c. Both
// read the projected record rather than the bytes, so re_insn_t has to be
// self sufficient for presentation and the IR never needs the image again.
void x64_render(const re_insn_t *in, re_arena_t *a, re_strbuf_t *out);
size_t x64_lower(const re_insn_t *in, re_ir_func_t *f, re_arena_t *a);
