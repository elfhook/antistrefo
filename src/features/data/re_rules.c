// re_rules.c - the capability rule table and its evaluator. Policy in one place.
// Module: feature (C11).
// Owns: rule definitions, signal matching, finding construction and emission.
// Depends: re_rules.h only. Whole image analysis, never code bodies.
#include "features/data/re_rules.h"

#include "features/data/re_triage.h"
#include "utils/text/re_hex.h"
#include "utils/text/re_str.h"
#include "utils/text/re_strbuf.h"

// Signal tables. Kept as literals so the whole policy set is greppable and a
// reviewer can audit what antistrefo claims without reading any logic.
static const re_signal_t kAntiDebugSigs[] = {
    {RE_SIG_IMPORT, "IsDebuggerPresent", 0},
    {RE_SIG_IMPORT, "CheckRemoteDebuggerPresent", 0},
    {RE_SIG_IMPORT, "NtQueryInformationProcess", 0},
    {RE_SIG_IMPORT, "ZwQueryInformationProcess", 0},
    {RE_SIG_IMPORT, "DbgBreakPoint", 0},
    {RE_SIG_IMPORT, "DbgUiRemoteBreakin", 0},
    {RE_SIG_BYTES, "OllyDbg", 0},
    {RE_SIG_BYTES, "x64dbg", 0},
    {RE_SIG_BYTES, "x32dbg", 0},
    {RE_SIG_BYTES, "WinDbg", 0},
    {RE_SIG_BYTES, "ScyllaHide", 0},
};

static const re_signal_t kAntiVmSigs[] = {
    {RE_SIG_BYTES, "VMwareVirtualPlatform", 0},
    {RE_SIG_BYTES, "VBoxGuest", 0},
    {RE_SIG_BYTES, "VBOX", 0},
    {RE_SIG_BYTES, "QEMU", 0},
    {RE_SIG_BYTES, "Xen", 0},
    {RE_SIG_BYTES, "vmtoolsd", 0},
};

static const re_signal_t kHideThreadSigs[] = {
    {RE_SIG_IMPORT, "ZwSetInformationThread", 0},
    {RE_SIG_IMPORT, "NtSetInformationThread", 0},
    {RE_SIG_BYTES, "ThreadHideFromDebugger", 0},
};

static const re_signal_t kPrivilegeSigs[] = {
    {RE_SIG_IMPORT, "AdjustTokenPrivileges", 0}, {RE_SIG_IMPORT, "SeDebugPrivilege", 0},
    {RE_SIG_IMPORT, "RtlAdjustPrivilege", 0},    {RE_SIG_IMPORT, "LookupPrivilegeValue", 0},
    {RE_SIG_BYTES, "SeDebugPrivilege", 0},       {RE_SIG_BYTES, "SeLoadDriverPrivilege", 0},
};

static const re_signal_t kInjectionSigs[] = {
    {RE_SIG_IMPORT, "WriteProcessMemory", 0}, {RE_SIG_IMPORT, "CreateRemoteThread", 0},
    {RE_SIG_IMPORT, "NtCreateThreadEx", 0},   {RE_SIG_IMPORT, "QueueUserAPC", 0},
    {RE_SIG_IMPORT, "SetWindowsHookEx", 0},   {RE_SIG_IMPORT, "NtMapViewOfSection", 0},
};

static const re_signal_t kUnbackedAllocSigs[] = {
    {RE_SIG_IMPORT, "VirtualAllocEx", 0},          {RE_SIG_IMPORT, "NtAllocateVirtualMemory", 0},
    {RE_SIG_IMPORT, "ZwAllocateVirtualMemory", 0}, {RE_SIG_IMPORT, "VirtualAlloc", 0},
    {RE_SIG_IMPORT, "RtlMoveMemory", 0},
};

static const re_signal_t kCryptoSigs[] = {
    {RE_SIG_CONST, NULL, 0x67452301u},     // MD5 and SHA-1 init constants
    {RE_SIG_CONST, NULL, 0x6a09e667u},     // SHA-256 init
    {RE_SIG_CONST, NULL, 0x5a827999u},     // SHA-1 round constant
    {RE_SIG_CONST, NULL, 0xedb88320u},     // CRC-32 table polynomial
    {RE_SIG_BYTES, "expand 32-byte k", 0}, // ChaCha20 and Salsa20
    {RE_SIG_BYTES, "AES", 0},
};

static const re_signal_t kNetworkSigs[] = {
    {RE_SIG_IMPORT, "WSAStartup", 0},    {RE_SIG_IMPORT, "connect", 0},
    {RE_SIG_IMPORT, "InternetOpenA", 0}, {RE_SIG_IMPORT, "WinHttpOpen", 0},
    {RE_SIG_BYTES, "http://", 0},        {RE_SIG_BYTES, "https://", 0},
    {RE_SIG_BYTES, "User-Agent", 0},
};

static const re_signal_t kCredentialSigs[] = {
    {RE_SIG_BYTES, "lsass", 0},
    {RE_SIG_BYTES, "sekurlsa", 0},
    {RE_SIG_BYTES, "mimikatz", 0},
    {RE_SIG_BYTES, "SAM\\", 0},
    {RE_SIG_BYTES, "\\Security\\Cache", 0},
    {RE_SIG_IMPORT, "CredEnumerateA", 0},
};

static const re_signal_t kPersistenceSigs[] = {
    {RE_SIG_BYTES, "CurrentVersion\\Run", 0},
    {RE_SIG_BYTES, "CurrentVersion\\RunOnce", 0},
    {RE_SIG_IMPORT, "RegSetValueEx", 0},
    {RE_SIG_IMPORT, "CreateService", 0},
};

static const re_signal_t kDriverSurfaceSigs[] = {
    {RE_SIG_KERNEL, NULL, 0},
    {RE_SIG_IMPORT, "IoCreateDevice", 0},
    {RE_SIG_IMPORT, "IofCompleteRequest", 0},
};

static const re_signal_t kPhysicalMemSigs[] = {
    {RE_SIG_IMPORT, "MmMapIoSpace", 0},
    {RE_SIG_IMPORT, "MmMapLockedPages", 0},
    {RE_SIG_IMPORT, "MmMapLockedPagesSpecifyCache", 0},
    {RE_SIG_IMPORT, "ZwMapViewOfSection", 0},
    {RE_SIG_IMPORT, "MmAllocateContiguousMemory", 0},
};

static const re_signal_t kObfuscationSigs[] = {
    {RE_SIG_THIN_IMPORTS, NULL, 5},
    {RE_SIG_DYN_RESOLVE, NULL, 0},
};

static const re_signal_t kPackedSigs[] = {
    {RE_SIG_SECTION_ENTROPY, NULL, 0},
    {RE_SIG_SECTION_ENTROPY, NULL, 0},
};

static const re_rule_t kRules[] = {
    {"anti-debug", "Anti debugging",
     "queries or reacts to a debugger, so analysis is expected to be resisted", 2, 12,
     kAntiDebugSigs, sizeof(kAntiDebugSigs) / sizeof(kAntiDebugSigs[0]), false},
    {"anti-vm", "Anti virtual machine", "detects a virtualised or emulated host", 1, 5, kAntiVmSigs,
     sizeof(kAntiVmSigs) / sizeof(kAntiVmSigs[0]), false},
    {"hide-thread", "Thread hidden from debugger",
     "marks its threads so a debugger will not see them", 2, 10, kHideThreadSigs,
     sizeof(kHideThreadSigs) / sizeof(kHideThreadSigs[0]), false},
    {"privilege", "Privilege manipulation",
     "adjusts process privileges, commonly to gain debug or driver load rights", 2, 10,
     kPrivilegeSigs, sizeof(kPrivilegeSigs) / sizeof(kPrivilegeSigs[0]), false},
    {"injection", "Remote code injection primitive",
     "can write into and execute in another process", 3, 20, kInjectionSigs,
     sizeof(kInjectionSigs) / sizeof(kInjectionSigs[0]), false},
    {"unbacked-alloc", "Unbacked executable memory",
     "allocates and fills memory that has no file backing", 1, 6, kUnbackedAllocSigs,
     sizeof(kUnbackedAllocSigs) / sizeof(kUnbackedAllocSigs[0]), false},
    {"crypto", "Cryptographic implementation", "carries crypto constants or a known cipher marker",
     1, 6, kCryptoSigs, sizeof(kCryptoSigs) / sizeof(kCryptoSigs[0]), false},
    {"network", "Network capability", "performs outbound network activity", 1, 6, kNetworkSigs,
     sizeof(kNetworkSigs) / sizeof(kNetworkSigs[0]), false},
    {"credential-access", "Credential material access",
     "references credential stores or known credential dumping tooling", 3, 18, kCredentialSigs,
     sizeof(kCredentialSigs) / sizeof(kCredentialSigs[0]), false},
    {"persistence", "Persistence mechanism", "registers itself to survive a reboot", 2, 10,
     kPersistenceSigs, sizeof(kPersistenceSigs) / sizeof(kPersistenceSigs[0]), false},
    {"driver-surface", "Kernel driver with an IOCTL surface",
     "is a native driver that creates a device and completes requests, so it is "
     "reachable from user mode",
     2, 14, kDriverSurfaceSigs, sizeof(kDriverSurfaceSigs) / sizeof(kDriverSurfaceSigs[0]), true},
    {"physical-memory", "Physical or arbitrary kernel memory mapping",
     "maps physical memory or a section into the kernel address space", 3, 24, kPhysicalMemSigs,
     sizeof(kPhysicalMemSigs) / sizeof(kPhysicalMemSigs[0]), false},
    {"obfuscation", "Likely obfuscation",
     "a very small import table combined with runtime API resolution", 2, 12, kObfuscationSigs,
     sizeof(kObfuscationSigs) / sizeof(kObfuscationSigs[0]), false},
    {"packed", "Packed or encrypted section",
     "a section whose entropy indicates compression or encryption", 2, 12, kPackedSigs,
     sizeof(kPackedSigs) / sizeof(kPackedSigs[0]), false},
    {"dynamic-device", "Device name built at runtime",
     "the device name is a format string, so static analysis cannot enumerate it", 1, 4, NULL, 0,
     false},
    {"no-pdb", "No debug directory", "carries no debug path, so build provenance is unknown", 0, 1,
     NULL, 0, false},
    {"unauthenticated-overlay", "Unauthenticated appended data",
     "data follows the last section and is not a signature, so it may hide a payload", 2, 10, NULL,
     0, false},
};

const re_rule_t *re_rule_table(size_t *count) {
    if (count)
        *count = sizeof(kRules) / sizeof(kRules[0]);
    return kRules;
}

const re_rule_t *re_rule_find(const char *id) {
    size_t n = 0;
    const re_rule_t *t = re_rule_table(&n);
    for (size_t i = 0; i < n; i++) {
        if (re_str_eq_cstr(re_str(t[i].id), id))
            return &t[i];
    }
    return NULL;
}

static bool has_import(const re_pe_t *pe, const char *name) {
    re_str_t want = re_str(name);
    for (size_t i = 0; i < RE_VEC_LEN(&pe->syms); i++) {
        const re_str_t *s = RE_VEC_PTR(&pe->syms, re_str_t, i);
        if (re_str_ieq_cstr(*s, want.p))
            return true;
    }
    return false;
}

static bool has_bytes(const re_strings_t *st, const char *needle) {
    re_str_t want = re_str(needle);
    for (size_t i = 0; i < RE_VEC_LEN(&st->hits); i++) {
        const re_str_hit_t *h = RE_VEC_PTR(&st->hits, re_str_hit_t, i);
        if (re_str_ieq_cstr(h->text, want.p))
            continue;
        if (h->text.n >= want.n) {
            for (size_t k = 0; k + want.n <= h->text.n; k++) {
                bool hit = true;
                for (size_t j = 0; j < want.n; j++) {
                    if (re_char_lower(h->text.p[k + j]) != re_char_lower(want.p[j])) {
                        hit = false;
                        break;
                    }
                }
                if (hit)
                    return true;
            }
        }
    }
    return false;
}

static bool has_const(re_span_t img, uint32_t v) {
    uint8_t pat[4];
    for (int i = 0; i < 4; i++)
        pat[i] = (uint8_t)(v >> (i * 8));
    for (size_t i = 0; i + 4 <= img.n; i++) {
        if (img.p[i] == pat[0] && img.p[i + 1] == pat[1] && img.p[i + 2] == pat[2] &&
            img.p[i + 3] == pat[3])
            return true;
    }
    return false;
}

// Data after the last section is normal when it is the Authenticode signature,
// which every signed driver has. Only call it a finding when nothing explains it.
static bool overlay_is_suspicious(const re_pe_t *pe) {
    uint32_t max_end = 0;
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        if (s->rptr + s->rsize > max_end)
            max_end = s->rptr + s->rsize;
    }
    if (!max_end)
        return false;
    if (pe->n_dirs > RE_PE_DD_SECURITY && pe->dd_size[RE_PE_DD_SECURITY] &&
        pe->dd_rva[RE_PE_DD_SECURITY] == max_end)
        return false;
    // The security directory field is a file offset, not an RVA, so a mismatch
    // here means the tail is unexplained.
    return pe->n_dirs <= RE_PE_DD_SECURITY || pe->dd_size[RE_PE_DD_SECURITY] == 0;
}

static bool fire(re_span_t img, const re_pe_t *pe, const re_strings_t *st, const re_signal_t *s) {
    switch (s->kind) {
        case RE_SIG_IMPORT:
            return has_import(pe, s->arg);
        case RE_SIG_STRING:
            return has_bytes(st, s->arg);
        case RE_SIG_BYTES:
            return has_bytes(st, s->arg);
        case RE_SIG_CONST:
            return has_const(img, (uint32_t)s->num);
        case RE_SIG_DYN_RESOLVE:
            return has_import(pe, "MmGetSystemRoutineAddress") || has_import(pe, "GetProcAddress");
        case RE_SIG_SECTION_ENTROPY:
            for (uint16_t i = 0; i < pe->n_sec; i++) {
                if (pe->sec[i].entropy > 7.0)
                    return true;
            }
            return false;
        case RE_SIG_DYNAMIC_DEVICE:
            return re_triage_has_dynamic_device(st, NULL);
        case RE_SIG_NO_PDB:
            return st->pdb.n == 0;
        case RE_SIG_OVERLAY:
            return overlay_is_suspicious(pe);
        case RE_SIG_THIN_IMPORTS:
            return RE_VEC_LEN(&pe->syms) < s->num && RE_VEC_LEN(&st->hits) > 20;
        case RE_SIG_KERNEL:
            return pe->subsystem == 1;
    }
    return false;
}

// A short, checkable description of which signal fired, so the agent can go
// verify it rather than trusting the verdict blindly.
static void evidence_of(re_arena_t *a, const re_signal_t *s, char *buf, size_t cap) {
    re_strbuf_t sb;
    re_strbuf_init(&sb, a);
    switch (s->kind) {
        case RE_SIG_IMPORT:
        case RE_SIG_STRING:
        case RE_SIG_BYTES:
            re_strbuf_appendf(&sb, "matches '%s'", s->arg ? s->arg : "?");
            break;
        case RE_SIG_CONST:
            re_strbuf_appendf(&sb, "constant 0x%08llx", (unsigned long long)s->num);
            break;
        case RE_SIG_SECTION_ENTROPY:
            re_strbuf_puts(&sb, "section entropy above 7.0");
            break;
        case RE_SIG_THIN_IMPORTS:
            re_strbuf_appendf(&sb, "fewer than %llu imports", (unsigned long long)s->num);
            break;
        default:
            re_strbuf_puts(&sb, "present");
            break;
    }
    for (size_t i = 0; sb.p && i + 1 < cap && i < sb.len; i++)
        buf[i] = sb.p[i];
    buf[cap - 1] = '\0';
}

static void push_finding(re_arena_t *a, re_vec_t *out, const re_rule_t *r, const char *evid) {
    re_finding_t f;
    f.id = r->id;
    f.name = r->name;
    f.severity = r->severity;
    f.score = r->score;
    f.evidence = re_arena_strdup(a, evid);
    RE_VEC_PUSH(out, a, f);
}

size_t re_rules_eval(re_span_t img, const re_pe_t *pe, const re_strings_t *st, re_arena_t *a,
                     re_vec_t *out) {
    re_vec_init(out, sizeof(re_finding_t));
    size_t n = 0;
    const re_rule_t *rules = re_rule_table(&n);
    char evid[96];
    for (size_t i = 0; i < n; i++) {
        const re_rule_t *r = &rules[i];
        const re_signal_t *fired = NULL;
        size_t hits = 0;
        for (size_t j = 0; j < r->n_sigs; j++) {
            if (fire(img, pe, st, &r->sigs[j])) {
                hits++;
                if (!fired)
                    fired = &r->sigs[j];
                if (!r->match_all)
                    break;
            }
        }
        bool matched = r->n_sigs == 0 ? false : (r->match_all ? hits == r->n_sigs : hits > 0);
        if (!matched)
            continue;
        if (fired) {
            evidence_of(a, fired, evid, sizeof(evid));
        } else {
            re_strbuf_t all;
            re_strbuf_init(&all, a);
            re_strbuf_appendf(&all, "all %zu signals present", r->n_sigs);
            for (size_t k = 0; all.p && k + 1 < sizeof(evid) && k < all.len; k++)
                evid[k] = all.p[k];
            evid[sizeof(evid) - 1] = '\0';
        }
        push_finding(a, out, r, evid);
    }
    return RE_VEC_LEN(out);
}

void re_rules_emit(re_jw_t *w, const re_vec_t *findings, bool include_info) {
    uint32_t score = 0;
    uint32_t high = 0;
    for (size_t i = 0; i < RE_VEC_LEN(findings); i++) {
        const re_finding_t *f = RE_VEC_PTR(findings, re_finding_t, i);
        if (f->severity == 0 && !include_info)
            continue;
        score += (uint32_t)f->score;
        if (f->severity == 3)
            high++;
    }
    re_jw_key(w, "capabilities");
    re_jw_obj(w);
    re_jw_ku64(w, "score", score);
    re_jw_ku64(w, "high_severity", high);
    re_jw_ku64(w, "count", RE_VEC_LEN(findings));
    re_jw_key(w, "findings");
    re_jw_arr(w);
    for (size_t i = 0; i < RE_VEC_LEN(findings); i++) {
        const re_finding_t *f = RE_VEC_PTR(findings, re_finding_t, i);
        if (f->severity == 0 && !include_info)
            continue;
        re_jw_obj(w);
        re_jw_kcstr(w, "id", f->id);
        re_jw_kcstr(w, "name", f->name);
        re_jw_ku64(w, "severity", (uint64_t)f->severity);
        re_jw_ku64(w, "score", (uint64_t)f->score);
        re_jw_kcstr(w, "evidence", f->evidence);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
    re_jw_obj_end(w);
}
