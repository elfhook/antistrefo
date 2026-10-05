#!/usr/bin/env python3
# obfuscate.py - build a synthetic PE carrying the idioms the tool claims to recover.
# Module: tool (Python 3).
# Owns: one generator laying out an opaque predicate, trampoline, stack string.
# Depends: stdlib only. The image layout mirrors tests/re_pe_fixture.h.
import struct
import sys

IMAGE_BASE = 0x180000000
TEXT_RVA = 0x1000
EDATA_RVA = 0x2000
HDRS = 0x200
OPT_SIZE = 0xF0

# Code layout, in the order the generator writes it:
#
#   +0x00  opaque predicate: rax = 0; test rax, rax; je taken
#   +0x08  call $+5 trampoline over a jmp into the string builder
#   +0x0A  jmp rel8 to the stack string builder
#   +0x0C  stack string stores: "sdrawkcab" built backwards, 10 bytes
#   ...    real body: mov eax, 0x40; ret
#
# Every idiom sits far enough from the others that a recovery that runs into one
# is not reading the next one's bytes.
CODE = []


def emit(*bs):
    CODE.extend(bs)


# --- the opaque predicate: mov eax,0 (B8 00..), test rax,rax (48 85 C0), je +2
emit(0xB8, 0, 0, 0, 0)          # mov eax, 0
emit(0x48, 0x85, 0xC0)          # test rax, rax
emit(0x74, 0x02)                # je +2 -> the trampoline below
emit(0x31, 0xC0)                # xor eax, eax (the never-taken arm)
emit(0xEB, 0x02)                # jmp +2 -> the trampoline

# --- the call $+5 trampoline: E8 00 00 00 00 then a jmp into the string builder
emit(0xE8, 0, 0, 0, 0)          # call $+5: pushes the address of the next byte
emit(0x5B)                      # pop rbx (the trampoline's whole payload)
# jmp rel8 to the string builder, whose rva is fixed once the layout below is
# set: the string builder sits right after this jmp.
emit(0xEB, 0x00)                # placeholder, patched below
PRED_END = len(CODE)

# --- the stack string: nine immediate stores to consecutive rsp offsets
# "sdrawkcab" written one byte at a time, which is what obfuscated code does to
# keep the literal out of the .rdata the strings pass scans.
STRING = b"sdrawkcab"
for i, ch in enumerate(STRING):
    emit(0xC6, 0x44, 0x24, 0x10 + i, ch)  # mov byte [rsp+0x10+i], ch
emit(0xB8, 0x40, 0, 0, 0)       # mov eax, 0x40
emit(0xC3)                      # ret

# patch the string builder's distance into the jmp back at PRED_END - 1
CODE[PRED_END - 1] = (len(CODE) - PRED_END) & 0xFF

CODE = bytes(CODE)
# The jump table lives in .rdata, where a pointer run belongs, and its entries
# point at the string builder and the trampoline: the two code addresses the
# walk recovered. A dispatch through it is the switch form the jtable pass reads.
JTABLE = struct.pack("<QQ", IMAGE_BASE + 0x16, IMAGE_BASE + 8)


def put16(b, off, v):
    b[off:off + 2] = struct.pack("<H", v)


def put32(b, off, v):
    b[off:off + 4] = struct.pack("<I", v & 0xFFFFFFFF)


def put64(b, off, v):
    b[off:off + 8] = struct.pack("<Q", v)


def build():
    edata_size = 0x60 + len(JTABLE)
    img = bytearray(HDRS + len(CODE) + edata_size)
    put16(img, 0, 0x5A4D)
    put32(img, 0x3C, 0x40)
    put32(img, 0x40, 0x00004550)
    coff = 0x44
    put16(img, coff + 0, 0x8664)     # machine
    put16(img, coff + 2, 2)          # sections
    put16(img, coff + 16, OPT_SIZE)
    put16(img, coff + 18, 0x0022)    # executable, large address aware
    opt = coff + 20
    put16(img, opt, 0x20B)           # PE32+
    put32(img, opt + 16, TEXT_RVA)   # entry
    put64(img, opt + 24, IMAGE_BASE)
    put32(img, opt + 56, TEXT_RVA * 2)
    put16(img, opt + 68, 3)          # console
    put32(img, opt + 108, 16)        # rva and sizes
    put32(img, opt + 112, EDATA_RVA) # export dir
    put32(img, opt + 116, edata_size)
    put32(img, opt + 136, EDATA_RVA + 0x40)  # exception dir, after the export dir
    put32(img, opt + 140, 24)        # one RUNTIME_FUNCTION
    sec = 0x148
    img[sec:sec + 5] = b".text"
    put32(img, sec + 8, len(CODE))
    put32(img, sec + 12, TEXT_RVA)
    put32(img, sec + 16, len(CODE))
    put32(img, sec + 20, HDRS)
    put32(img, sec + 36, 0x60000020)
    img[HDRS:HDRS + len(CODE)] = CODE
    ed = HDRS + len(CODE)
    # the jump table lands at .rdata + 0x58, past the export directory fields
    jt_off = ed + 0x58
    img[jt_off:jt_off + len(JTABLE)] = JTABLE
    img[ed:ed + 6] = b".rdata"
    put32(img, ed + 8, edata_size)
    put32(img, ed + 12, EDATA_RVA)
    put32(img, ed + 16, edata_size)
    put32(img, ed + 20, HDRS + len(CODE))
    put32(img, ed + 36, 0x40000040)
    # one export naming the entry
    names = EDATA_RVA + 0x20
    put32(img, ed + 0x00, 0)
    put32(img, ed + 0x0C, EDATA_RVA + 0x30)
    put32(img, ed + 0x10, 1)
    put32(img, ed + 0x14, 1)
    put32(img, ed + 0x18, 1)
    put32(img, ed + 0x1C, EDATA_RVA + 0x18)  # functions
    put32(img, ed + 0x20, EDATA_RVA + 0x1C)  # names
    put32(img, ed + 0x24, EDATA_RVA + 0x20)  # ordinals
    put32(img, ed + 0x18, TEXT_RVA)
    img[EDATA_RVA - EDATA_RVA + 0x18 + (HDRS + len(CODE) - EDATA_RVA + EDATA_RVA if False else 0):]  # no-op
    base = HDRS + len(CODE)
    put32(img, base + 0x18, TEXT_RVA)
    name = b"obf_entry"
    img[base + 0x1C:base + 0x1C + 4] = struct.pack("<I", EDATA_RVA + 0x28)
    img[base + 0x20:base + 0x22] = struct.pack("<H", 0)
    img[base + 0x28:base + 0x28 + len(name) + 1] = name + b"\0"
    img[base + 0x30:base + 0x30 + 9] = b"obf.dll\0"
    # RUNTIME_FUNCTION covering the whole code, unwind rva naming the .rdata pad
    put32(img, base + 0x40, TEXT_RVA)
    put32(img, base + 0x44, TEXT_RVA + len(CODE))
    put32(img, base + 0x48, EDATA_RVA + 0x50)
    return bytes(img)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: obfuscate.py <out.exe>", file=sys.stderr)
        raise SystemExit(2)
    with open(sys.argv[1], "wb") as f:
        f.write(build())
    print(f"wrote {sys.argv[1]} ({HDRS + len(CODE) + 0x60} bytes)")
