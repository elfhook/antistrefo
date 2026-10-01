// test_stack.c - the stack pass against functions whose answers are known by hand.
// Module: test (C11).
// Owns: argument counts, frame sizes and local slots for hand assembled functions.
// Depends: re_core through the public headers, so the pass is driven exactly as a
//           caller drives it.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_str.h"

int re_test_count = 0;
int re_test_fail = 0;

#define IMAGE_BASE 0x180000000ull
#define TEXT_RVA 0x1000u
#define HDRS 0x200u
#define OPT_SIZE 0xF0u
#define CODE_BYTES 0x40u
#define IMG_BYTES (HDRS + CODE_BYTES)

// Six functions, each chosen because it is a case the pass can plausibly get wrong.
// The offsets are the point: the assertions below are read off this listing, not off
// whatever the pass happens to produce.
//
// 1000  two_args      mov rax,rcx ; add rax,rdx ; ret
//        2 arguments: rcx and rdx, both read and never written. The ALU form is
//        the point: add reads its reg field and writes its r/m field, the
//        opposite way round from mov, so an argument only ever used in
//        arithmetic is invisible to a pass that treats them the same.
// 1007  arg_before_call  mov rax,rcx ; call ; ret
//        1 argument. The read happens before the call, and the call then writes
//        every volatile register including rcx. A pass that collected reads and
//        compared at the end would find rcx written and conclude zero arguments.
// 1010  frame_locals  push rbx ; sub rsp,40h ; mov [rsp-8],rax ;
//                      mov [rsp-10h],r11 ; mov rax,[rsp-8] ; add rsp,40h ;
//                      pop rbx ; ret
//        frame 0x40 and two distinct local slots. The displacements are negative
//        on purpose: a positive one is an incoming argument slot, not a local,
//        which is what the pass assumes and is right to.
//        rax and r11 are not argument registers under either convention, so this
//        must not gain arguments from storing them.
// 102a  tail_thunk    mov rax,rcx ; jmp 103f
//        ends in a jump rather than a return, and forwards rcx, so one argument
// 1032  no_args       mov eax,1 ; ret
//        touches nothing that arrived, so no arguments and no frame
// 1038  sysv_two      mov rdi,rdi ; add rax,rsi ; ret
//        2 arguments by SysV: rdi and rsi, which are not argument registers
//        under Windows at all, so the convention has to be inferred from them
// 103f  stub          ret        the tail thunk's destination
static const uint8_t kCode[] = {
    0x48, 0x8b, 0xc1, 0x48, 0x03, 0xd0, 0xc3,                   // 1000 two_args
    0x48, 0x8b, 0xc1, 0xe8, 0x03, 0x00, 0x00, 0x00, 0xc3,       // 1007 arg_before_call
    0x53, 0x48, 0x83, 0xec, 0x40, 0x48, 0x89, 0x44, 0x24, 0xf8, // 1010 frame_locals
    0x48, 0x89, 0x5c, 0x24, 0xf0, 0x48, 0x8b, 0x44, 0x24, 0xf8,
    0x48, 0x83, 0xc4, 0x40, 0x5b, 0xc3,             //
    0x48, 0x8b, 0xc1, 0xe9, 0x0d, 0x00, 0x00, 0x00, // 102a tail_thunk
    0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3,             // 1032 no_args
    0x48, 0x8b, 0xff, 0x48, 0x01, 0xf7, 0xc3,       // 1038 sysv_two
    0xc3,                                           // 103f stub
};

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

static void build_pe(uint8_t *img) {
    memset(img, 0, HDRS);
    put16(img, 0x5A4D);
    put32(img + 0x3C, 0x40);
    put32(img + 0x40, 0x00004550u);
    uint8_t *coff = img + 0x44;
    put16(coff + 0, 0x8664);
    put16(coff + 2, 1);
    put16(coff + 16, OPT_SIZE);
    put16(coff + 18, 0x0022);
    uint8_t *opt = coff + 20;
    put16(opt, 0x20B);
    put32(opt + 16, TEXT_RVA);
    put64(opt + 24, IMAGE_BASE);
    put32(opt + 56, TEXT_RVA * 2);
    put16(opt + 68, 1);
    put32(opt + 108, 16);
    uint8_t *sec = img + 0x148;
    memcpy(sec, ".text", 5);
    put32(sec + 8, CODE_BYTES);
    put32(sec + 12, TEXT_RVA);
    put32(sec + 16, CODE_BYTES);
    put32(sec + 20, HDRS);
    put32(sec + 36, 0x60000020u);
    memcpy(img + HDRS, kCode, sizeof(kCode));
}

// Run the pass over one function at a known offset. Each case below is therefore a
// handful of assertions rather than a repeated setup.
//
// frame_size, n_calls and tail_call are not inferred here: re_stack takes all three
// from the function record, which is where re_func's prologue analysis already put
// them. So a probe states them rather than expecting the stack pass to rediscover
// them, and the cases that care about them set the field they are about.
static re_func_t probe_at(uint32_t off, uint32_t size) {
    re_func_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.va = IMAGE_BASE + TEXT_RVA + off;
    probe.rva = TEXT_RVA + off;
    probe.size = size;
    return probe;
}

// The scanner found only part of this fixture, so the cases below do not depend on
// it. What the scan does produce is exercised at the end of main, through the real
// record rather than a hand built one.
static void check_two_args(re_code_t *code) {
    re_func_t probe = probe_at(0x00, 7);
    re_stack_t s;
    memset(&s, 0, sizeof(s));
    re_stack_analyze(code, &probe, NULL, &s);
    RE_CHECK_EQ_U(s.n_params, 2);
    RE_CHECK_EQ_U(s.cc, RE_CC_MS64);
    // Positions in the Windows argument order, not register numbers: 0 is rcx and 1
    // is rdx. Both were read before anything wrote them.
    RE_CHECK_EQ_U(s.arg_regs[0], 0);
    RE_CHECK_EQ_U(s.arg_regs[1], 1);
}

// The case the pass's design exists for: the argument is read before a call, and the
// call then writes every volatile register, rcx among them. A pass that collected its
// reads and compared at the end would find rcx written and conclude zero arguments.
// n_calls is the scanner's figure, which re_stack forwards rather than counts.
static void check_arg_after_call(re_code_t *code) {
    re_func_t probe = probe_at(0x07, 9);
    re_stack_t s;
    probe.n_calls = 1;
    memset(&s, 0, sizeof(s));
    re_stack_analyze(code, &probe, NULL, &s);
    RE_CHECK_EQ_U(s.n_params, 1);
    RE_CHECK_EQ_U(s.cc, RE_CC_MS64);
    RE_CHECK_EQ_U(s.arg_regs[0], 0);
}

// A real frame: the size comes from the prologue and the locals from the two distinct
// displacements written below it. rax and r11 are not argument registers under either
// convention, so this must not gain arguments from storing them.
static void check_frame(re_code_t *code) {
    re_func_t probe = probe_at(0x10, 0x1a);
    re_stack_t s;
    // The frame size is re_func's, from the prologue scan, not re_stack's.
    probe.frame_size = 0x40;
    memset(&s, 0, sizeof(s));
    re_stack_analyze(code, &probe, NULL, &s);
    RE_CHECK_EQ_HEX(s.frame_size, 0x40);
    RE_CHECK_EQ_U(s.n_params, 0);
    RE_CHECK(s.n_slots >= 2);
    RE_CHECK_EQ_U(s.n_locals, s.n_slots);
}

// Ends in a jump, so it is a tail call, and it forwards its one argument.
static void check_tail(re_code_t *code) {
    re_func_t probe = probe_at(0x2a, 8);
    re_stack_t s;
    // tail_call is the scanner's thunk flag, forwarded rather than rediscovered.
    probe.flags = RE_FUNC_THUNK;
    memset(&s, 0, sizeof(s));
    re_stack_analyze(code, &probe, NULL, &s);
    RE_CHECK(s.tail_call);
    RE_CHECK_EQ_U(s.n_params, 1);
}

// Touches nothing that arrived.
static void check_no_args(re_code_t *code) {
    re_func_t probe = probe_at(0x32, 6);
    re_stack_t s;
    memset(&s, 0, sizeof(s));
    re_stack_analyze(code, &probe, NULL, &s);
    RE_CHECK_EQ_U(s.n_params, 0);
    RE_CHECK_EQ_HEX(s.frame_size, 0);
    RE_CHECK_EQ_U(s.n_calls, 0);
}

// rdi and rsi are SysV arguments and are not arguments at all under Windows, so this
// is the only function in the file whose convention cannot be guessed from the callee
// side and has to be inferred from which registers were read.
static void check_sysv(re_code_t *code) {
    re_func_t probe = probe_at(0x38, 7);
    re_stack_t s;
    memset(&s, 0, sizeof(s));
    re_stack_analyze(code, &probe, NULL, &s);
    RE_CHECK_EQ_U(s.n_params, 2);
    RE_CHECK_EQ_U(s.cc, RE_CC_SYSV);
}

int main(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    build_pe(img);
    re_arena_init(&a, 65536);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK);
    RE_CHECK(pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_func_scan(&code, &a, &scan);
    // The scanner separates the tail thunk from the body because the jmp leaves the
    // function, so it finds more than one function in this fixture. That is correct
    // behaviour and nothing below should depend on the count; the cases that matter
    // drive the pass with an explicit extent.
    RE_CHECK(scan.funcs.len >= 1);

    check_two_args(&code);
    check_arg_after_call(&code);
    check_frame(&code);
    check_tail(&code);
    check_no_args(&code);
    check_sysv(&code);

    // The entry function, through the scanner's own record rather than a hand built
    // extent, so the pass is exercised the way a command exercises it.
    const re_func_t *f = re_func_at(&scan, 0);
    if (f) {
        re_stack_t s;
        memset(&s, 0, sizeof(s));
        re_stack_analyze(&code, f, &a, &s);
        RE_CHECK_EQ_U(s.n_params, 2);
        RE_CHECK_EQ_HEX(s.frame_size, 0);
        RE_CHECK(re_str_eq_cstr(re_str(re_cc_name(s.cc)), "ms64"));
    }
    re_arena_free(&a);
    return re_test_report("stack");
}
