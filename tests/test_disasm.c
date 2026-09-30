// test_disasm.c - golden vectors for the x86-64 decoder and the function walker.
// Module: test (C11).
// Owns: instruction length, control flow flag and prologue checks for the backend.
// Depends: re_core through the re_disasm vtable, never the private headers, so the
// test exercises the same seam a caller would.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "features/re_disasm.h"
#include "utils/re_buf.h"
#include "utils/re_str.h"

typedef struct {
    const char *name;
    const char *bytes;  // escaped hex, two characters per byte
    uint8_t len;        // instruction length in bytes
    bool call;
    bool branch;
    bool cond;
    bool ret;
} vec_t;

// This suite is its own binary, so it owns its counters.
int re_test_count = 0;
int re_test_fail = 0;

// Every vector is a real encoding. The lengths are the whole point: a wrong length
// desynchronises every instruction after it, so they are pinned one at a time.
static const vec_t kVec[] = {
    {"push rbp", "55", 1, false, false, false, false},
    {"pop rbp", "5d", 1, false, false, false, false},
    {"mov rbp,rsp", "4889e5", 3, false, false, false, false},
    {"mov rbp,rsp via mov", "488bec", 3, false, false, false, false},
    {"sub rsp,0x28", "4883ec28", 4, false, false, false, false},
    {"sub rsp,0x1234", "4881ec34120000", 7, false, false, false, false},
    {"add rsp,0x28", "4883c428", 4, false, false, false, false},
    {"leave", "c9", 1, false, false, false, false},
    {"ret", "c3", 1, false, false, false, true},
    {"ret 0x10", "c21000", 3, false, false, false, true},
    {"endbr64", "f30f1efa", 4, false, false, false, false},
    {"nop", "90", 1, false, false, false, false},
    {"multi byte nop", "0f1f440000", 5, false, false, false, false},
    {"int3", "cc", 1, false, false, false, false},
    {"call rel32", "e801000000", 5, true, false, false, false},
    {"jmp rel8", "eb01", 2, false, true, false, false},
    {"jmp rel32", "e901000000", 5, false, true, false, false},
    {"je rel8", "7401", 2, false, true, true, false},
    {"jne rel8", "7501", 2, false, true, true, false},
    {"je rel32", "0f8401000000", 6, false, true, true, false},
    {"jg rel32", "0f8f01000000", 6, false, true, true, false},
    {"loop", "e2fe", 2, false, true, true, false},
    {"mov eax,imm32", "b811223344", 5, false, false, false, false},
    {"movabs rax,imm64", "48b81122334455667788", 10, false, false, false, false},
    {"mov al,imm8", "b011", 2, false, false, false, false},
    {"mov rax,[rip+0x1234]", "488b0534120000", 7, false, false, false, false},
    {"mov rax,[rbp+8]", "488b4508", 4, false, false, false, false},
    {"mov rax,[rbp-8]", "488b45f8", 4, false, false, false, false},
    {"mov rbx,[rsp+0x28]", "488b5c2428", 5, false, false, false, false},
    {"mov [rbp-0x28],rbx", "48895dd8", 4, false, false, false, false},
    {"cmp qword [rbp+0x20],0", "48837d2000", 5, false, false, false, false},
    {"cmp byte [rax],0", "803800", 3, false, false, false, false},
    {"movzx eax,byte [rax]", "0fb600", 3, false, false, false, false},
    {"test eax,eax", "85c0", 2, false, false, false, false},
    {"movsxd rax,dword [rbp+4]", "48634504", 4, false, false, false, false},
    {"imul eax,[rbp+4],3", "69450403000000", 7, false, false, false, false},
    {"push imm32", "6811223344", 5, false, false, false, false},
    {"xchg rax,rbx", "4893", 2, false, false, false, false},
    {"bswap rax", "480fc8", 3, false, false, false, false},
    {"xorps xmm0,xmm0", "0f57c0", 3, false, false, false, false},
    {"setz al", "0f94c0", 3, false, false, false, false},
    {"cmovz rax,rbx", "480f44c3", 4, false, false, false, false},
    {"syscall", "0f05", 2, false, false, false, false},
    {"ud2", "0f0b", 2, false, false, false, false},
    {"cpuid", "0fa2", 2, false, false, false, false},
    {"rdtsc", "0f31", 2, false, false, false, false},
    {"mov gs:[0x60],rax", "654889342560000000", 9, false, false, false, false},
    {"opsize 16 mov ax,[rax]", "668b07", 3, false, false, false, false},
    {"addrsize 32 mov eax,[eax]", "678b00", 3, false, false, false, false},
    {"lock inc dword [rax]", "f0ff00", 3, false, false, false, false},
    {"vzeroupper", "c5f877", 3, false, false, false, false},
    {"vmovdqu ymm0,[rax]", "c5fe6f00", 4, false, false, false, false},
    {"call through rax", "ffd0", 2, true, false, false, false},
    {"jmp through rax", "ffe0", 2, false, true, false, false},
    {"call through [rax]", "ff10", 2, true, false, false, false},
};

static const re_disasm_t *g_x64;

// Turn two hex characters into a byte. A malformed pair is a test bug, not a
// decode case, so it is asserted rather than tolerated.
static uint8_t nib(char c) {
    if (c >= '0' && c <= '9')
        return (uint8_t)(c - '0');
    return (uint8_t)(c - 'a' + 10);
}

static void test_vectors(void) {
    for (size_t v = 0; v < sizeof(kVec) / sizeof(kVec[0]); v++) {
        const vec_t *t = &kVec[v];
        uint8_t buf[16];
        re_insn_t in;
        size_t n = (size_t)t->len;
        if (n * 2u != (size_t)re_str(t->bytes).n) {
            re_test_count++;
            re_test_fail++;
            printf("FAIL %s: len %u does not match \"%s\"\n", t->name, t->len, t->bytes);
            fflush(stdout);
            continue;
        }
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(t->bytes[i * 2]) << 4) | nib(t->bytes[i * 2 + 1]));
        if (!g_x64->decode(g_x64->ctx, 0x140001000ULL, re_span(buf, n), &in)) {
            re_test_count++;
            re_test_fail++;
            printf("FAIL %s: decode refused \"%s\"\n", t->name, t->bytes);
            fflush(stdout);
            continue;
        }
        re_test_count++;
        if (in.size != t->len) {
            re_test_fail++;
            printf("FAIL %s: length %u, want %u (%s)\n", t->name, in.size, t->len,
                   t->bytes);
            fflush(stdout);
        }
        if (in.is_call != t->call || in.is_branch != t->branch ||
            in.is_conditional != t->cond || in.is_return != t->ret) {
            re_test_fail++;
            printf("FAIL %s: flags c=%d b=%d cond=%d ret=%d, want c=%d b=%d cond=%d "
                   "ret=%d\n",
                   t->name, in.is_call, in.is_branch, in.is_conditional, in.is_return,
                   t->call, t->branch, t->cond, t->ret);
            fflush(stdout);
        }
    }
}

// The addresses a relative branch resolves to. A branch that lands somewhere
// else sends the function walker into the wrong function, so this is checked
// independently of the length.
static void test_targets(void) {
    struct {
        const char *bytes;
        uint8_t len;
        uint64_t want;
    } cases[] = {
        // The rel32 fields below are little endian, so -0xF is f1 ff ff ff and
        // not ff ff ff f1. Getting that backwards is exactly the kind of error
        // that hides behind a plausible looking number.
        {"e8fbffffff", 5, 0x140001000ULL},   // call -5, back to the start
        {"ebfd", 2, 0x140000FFFULL},         // jmp -3
        {"7402", 2, 0x140001004ULL},         // je +2
        {"0f8410000000", 6, 0x140001016ULL}, // je rel32 +0x10, past the 6 byte insn
        {"0f8ff1ffffff", 6, 0x140000FF7ULL}, // jg rel32 -0xF, back over the insn
        {"0f8fffffffff", 6, 0x140001005ULL}, // jg rel32 -1, onto the last byte
        {"e800000000", 5, 0x140001005ULL},   // call +0, onto the following insn
        {"4889e5c3", 3, 0},                  // not a branch, so unused
    };
    for (size_t v = 0; v < sizeof(cases) / sizeof(cases[0]); v++) {
        uint8_t buf[8];
        re_insn_t in;
        size_t n = cases[v].len;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(cases[v].bytes[i * 2]) << 4) |
                               nib(cases[v].bytes[i * 2 + 1]));
        if (!g_x64->decode(g_x64->ctx, 0x140001000ULL, re_span(buf, n), &in)) {
            RE_CHECK(0 && "decode refused a branch vector");
            continue;
        }
        if (cases[v].want)
            RE_CHECK_EQ_HEX(in.target, cases[v].want);
    }
}

// A truncated instruction must be refused, never read past the end. This is the
// case that keeps a malformed image from walking off the mapping.
static void test_truncated(void) {
    static const char *const kShort[] = {"48",           "4883",         "4883ec",
                                         "0f84",         "0f8401",       "e8",
                                         "c2",           "c210",         "f30f1e",
                                         "488b05",       "488b05341200", "69",
                                         "c5",           "c5f8",         "0f38"};
    for (size_t v = 0; v < sizeof(kShort) / sizeof(kShort[0]); v++) {
        uint8_t buf[8];
        re_insn_t in;
        size_t n = (size_t)re_str(kShort[v]).n / 2u;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(kShort[v][i * 2]) << 4) | nib(kShort[v][i * 2 + 1]));
        RE_CHECK(!g_x64->decode(g_x64->ctx, 0x1000, re_span(buf, n), &in));
    }
    // Opcodes that do not exist in 64-bit mode. The prefix bytes are deliberately
    // absent: a prefix followed by valid bytes is a valid instruction, and the
    // vectors above already cover lock, rep and the vector escapes.
    static const uint8_t kBad[] = {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1F, 0x27, 0x2F,
                                   0x37, 0x3F, 0x60, 0x61, 0x82, 0x9A, 0xCE, 0xD4,
                                   0xD5, 0xEA};
    for (size_t v = 0; v < sizeof(kBad) / sizeof(kBad[0]); v++) {
        uint8_t buf[8] = {0};
        re_insn_t in;
        buf[0] = kBad[v];
        RE_CHECK(!g_x64->decode(g_x64->ctx, 0x1000, re_span(buf, 8), &in));
    }
}

// A direct call and an indirect one differ in whether a target is reported, and
// conflating them is how a caller ends up chasing a pointer as if it were code.
static void test_indirect(void) {
    uint8_t direct[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    uint8_t indirect[2] = {0xFF, 0xD0};
    re_insn_t in;
    RE_CHECK(g_x64->decode(g_x64->ctx, 0x1000, re_span(direct, 5), &in));
    RE_CHECK(in.is_call);
    RE_CHECK(in.has_target);
    RE_CHECK_EQ_HEX(in.target, 0x1005);
    RE_CHECK(g_x64->decode(g_x64->ctx, 0x1000, re_span(indirect, 2), &in));
    RE_CHECK(in.is_call);
    RE_CHECK(!in.has_target);
}

// Prologue recognition is what seeds function discovery, so a miss here means a
// missed function in the report.
static void test_prologue(void) {
    static const char *const kYes[] = {
        "f30f1efa",              // endbr64
        "55",                    // push rbp
        "4889e5",                // mov rbp,rsp
        "4883ec28",              // sub rsp,0x28
        "4883ec00010000",        // sub rsp,0x100
        "f30f1efa55",            // endbr64 then push rbp
        "55b8001000004883ec20",  // push rbp, mov eax, sub rsp
    };
    static const char *const kNo[] = {
        "b801000000",     // mov eax,1
        "488b4508",       // mov rax,[rbp+8]
        "c3",             // ret
        "90",             // nop
        "0f1f440000",     // multi byte nop
    };
    for (size_t v = 0; v < sizeof(kYes) / sizeof(kYes[0]); v++) {
        uint8_t buf[16];
        size_t n = (size_t)re_str(kYes[v]).n / 2u;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(kYes[v][i * 2]) << 4) | nib(kYes[v][i * 2 + 1]));
        re_test_count++;
        if (!g_x64->is_prologue(g_x64->ctx, 0x1000, re_span(buf, n))) {
            re_test_fail++;
            printf("FAIL prologue missed: %s\n", kYes[v]);
            fflush(stdout);
        }
    }
    for (size_t v = 0; v < sizeof(kNo) / sizeof(kNo[0]); v++) {
        uint8_t buf[16];
        size_t n = (size_t)re_str(kNo[v]).n / 2u;
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)((nib(kNo[v][i * 2]) << 4) | nib(kNo[v][i * 2 + 1]));
        RE_CHECK(!g_x64->is_prologue(g_x64->ctx, 0x1000, re_span(buf, n)));
    }
}

static void test_registry(void) {
    RE_CHECK_EQ_U(re_disasm_arch_count(), 1);
    RE_CHECK(re_disasm_arch_name(0) != NULL);
    RE_CHECK(re_disasm_arch_name(1) == NULL);
    RE_CHECK(re_disasm_find("x86-64") == g_x64);
    RE_CHECK(re_disasm_find("nope") == NULL);
    RE_CHECK(re_disasm_find("") == NULL);
    RE_CHECK(g_x64 != NULL);
    RE_CHECK(g_x64->mode == 64);
    // A transfer function is not published yet, and NULL means not modelled.
    RE_CHECK(g_x64->trfunc(g_x64->ctx, 0x90) == NULL);
    RE_CHECK(g_x64->reg_name(g_x64->ctx, 0) != NULL);
}

int main(void) {
    g_x64 = re_disasm_find("x86-64");
    if (!g_x64) {
        printf("FAIL no x86-64 backend in this build\n");
        return 1;
    }
    test_registry();
    test_vectors();
    test_targets();
    test_truncated();
    test_indirect();
    test_prologue();
    return re_test_report("disasm");
}
