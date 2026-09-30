// re_format.c - magic detection for every format the project recognises.
// Module: feature (C11).
// Owns: the magic table and the small amount of cross checking it needs.
// Depends: re_format.h only. No I/O, no globals beyond a const name table.
#include "features/re_format.h"

static bool has(re_span_t s, uint64_t off, const void *bytes, size_t n) {
    re_span_t v = re_span_sub(s, off, n);
    if (!re_span_valid(v))
        return false;
    const uint8_t *p = (const uint8_t *)bytes;
    for (size_t i = 0; i < n; i++) {
        if (v.p[i] != p[i])
            return false;
    }
    return true;
}

static uint16_t rd16be(re_span_t s, uint64_t off) {
    re_span_t v = re_span_sub(s, off, 2);
    if (!re_span_valid(v))
        return 0;
    return (uint16_t)(((uint16_t)v.p[0] << 8) | v.p[1]);
}

static uint16_t rd16le(re_span_t s, uint64_t off) {
    re_span_t v = re_span_sub(s, off, 2);
    if (!re_span_valid(v))
        return 0;
    return (uint16_t)((uint16_t)v.p[0] | ((uint16_t)v.p[1] << 8));
}

static uint32_t rd32le(re_span_t s, uint64_t off) {
    re_span_t v = re_span_sub(s, off, 4);
    if (!re_span_valid(v))
        return 0;
    return (uint32_t)v.p[0] | ((uint32_t)v.p[1] << 8) | ((uint32_t)v.p[2] << 16) |
           ((uint32_t)v.p[3] << 24);
}

re_format_t re_format_detect(re_span_t img) {
    static const uint8_t elfmag[4] = {0x7f, 'E', 'L', 'F'};
    static const uint8_t wasm[4] = {0x00, 0x61, 0x73, 0x6d};
    static const uint8_t mz[2] = {'M', 'Z'};
    static const uint8_t ne[2] = {'N', 'E'};
    static const uint8_t le[2] = {'L', 'E'};
    static const uint8_t pe[4] = {'P', 'E', 0x00, 0x00};
    static const uint8_t macho_be32[4] = {0xfe, 0xed, 0xfa, 0xce};
    static const uint8_t macho_be64[4] = {0xfe, 0xed, 0xfa, 0xcf};
    static const uint8_t macho_le32[4] = {0xce, 0xfa, 0xed, 0xfe};
    static const uint8_t macho_le64[4] = {0xcf, 0xfa, 0xed, 0xfe};
    static const uint8_t fat_be[4] = {0xca, 0xfe, 0xba, 0xbe};
    static const uint8_t fat_le[4] = {0xbe, 0xba, 0xfe, 0xca};
    if (has(img, 0, elfmag, 4))
        return RE_FMT_ELF;
    if (has(img, 0, wasm, 4))
        return RE_FMT_WASM;
    if (has(img, 0, macho_le64, 4) || has(img, 0, macho_le32, 4) || has(img, 0, macho_be64, 4) ||
        has(img, 0, macho_be32, 4))
        return RE_FMT_MACHO;
    if (has(img, 0, fat_be, 4) || has(img, 0, fat_le, 4))
        return RE_FMT_MACHO_FAT;
    if (has(img, 0, mz, 2)) {
        uint32_t lfanew = rd32le(img, 0x3C);
        if (has(img, lfanew, pe, 4))
            return RE_FMT_PE;
        return RE_FMT_DOS;
    }
    if (has(img, 0, ne, 2))
        return RE_FMT_NE;
    if (has(img, 0, le, 2))
        return RE_FMT_LE;
    return RE_FMT_UNKNOWN;
}

const char *re_format_name(re_format_t f) {
    switch (f) {
        case RE_FMT_PE:
            return "pe";
        case RE_FMT_ELF:
            return "elf";
        case RE_FMT_MACHO:
            return "macho";
        case RE_FMT_MACHO_FAT:
            return "macho_fat";
        case RE_FMT_DOS:
            return "dos";
        case RE_FMT_NE:
            return "ne";
        case RE_FMT_LE:
            return "linear_exe";
        case RE_FMT_WASM:
            return "wasm";
        default:
            return "unknown";
    }
}

const char *re_format_arch_hint(re_span_t img, re_format_t f) {
    if (f == RE_FMT_ELF) {
        uint8_t cls = img.p && img.n > 4 ? img.p[4] : 0;
        uint8_t data = img.p && img.n > 5 ? img.p[5] : 0;
        if (cls == 2)
            return data == 2 ? "x64" : (data == 1 ? "x86" : "elf64");
        if (cls == 1)
            return data == 2 ? "arm" : "elf32";
        return "unknown";
    }
    if (f == RE_FMT_MACHO)
        return rd16be(img, 4) == 0x0100 ? "x86_64" : "macho32";
    if (f == RE_FMT_PE) {
        uint32_t lfanew = rd32le(img, 0x3C);
        uint16_t machine = rd16le(img, lfanew + 4);
        switch (machine) {
            case 0x8664:
                return "x64";
            case 0x014c:
                return "x86";
            case 0xAA64:
                return "arm64";
            case 0x01c0:
            case 0x01c4:
                return "arm";
            default:
                return "unknown";
        }
    }
    return "unknown";
}

bool re_format_has_image_base(re_format_t f) {
    return f == RE_FMT_PE || f == RE_FMT_ELF || f == RE_FMT_MACHO;
}
