// re_triage.c - risk classification and the triage response body.
// Module: feature (C11).
// Owns: the kernel API policy table, signal detection, and the triage JSON.
// Depends: re_triage.h only. Static analysis of headers, never of code bodies.
#include "features/re_rules.h"
#include "features/re_triage.h"

#include "utils/re_hash.h"
#include "utils/re_hex.h"
#include "utils/re_time.h"

// Weight is a triage priority, not a severity claim. Anything that maps
// physical or kernel virtual memory can reach arbitrary kernel state, so it
// scores high; the device lifecycle APIs are simply the price of being a driver.
static const re_kernel_api_t kKernelApis[] = {
    {"MmMapIoSpace", "maps physical memory into the kernel address space", 3},
    {"MmMapLockedPages", "maps locked pages, the classic arbitrary physical access", 3},
    {"MmMapLockedPagesSpecifyCache", "maps locked pages with a caller chosen cache type", 3},
    {"MmUnmapLockedPages", "releases a locked page mapping", 2},
    {"MmAllocateContiguousMemory", "allocates physically contiguous memory", 3},
    {"MmFreeContiguousMemory", "releases contiguous physical memory", 2},
    {"MmGetSystemRoutineAddress",
     "resolves APIs at runtime, so imports understate "
     "the real surface",
     3},
    {"MmGetSystemAddressForMdl", "maps an MDL into the kernel address space", 3},
    {"MmBuildMdlFromNonPagedPool", "builds an MDL over pool memory", 2},
    {"MmUnmapIoSpace", "releases a physical mapping", 1},
    {"ProbeForRead", "probes user memory for read access", 1},
    {"ProbeForWrite", "probes user memory for write access", 2},
    {"IoAllocateMdl", "allocates an MDL, the start of an arbitrary map chain", 2},
    {"IoGetDeviceObjectPointer", "takes a device object reference from a caller", 2},
    {"ZwOpenSection", "opens a section, the first step of a view mapping chain", 3},
    {"ZwMapViewOfSection", "maps a view, with a caller chosen base", 3},
    {"ZwQuerySystemInformation", "reads kernel state, often including module lists", 2},
    {"PsSetCreateProcessNotifyRoutine", "registers a process creation callback", 1},
    {"PsSetLoadImageNotifyRoutine", "registers an image load callback", 1},
    {"KeStackAttachProcess", "attaches to another process address space", 3},
    {"KeUnstackDetachProcess", "detaches from another process address space", 1},
    {"ObReferenceObjectByHandle", "resolves an arbitrary handle to an object", 2},
    {"RtlInitUnicodeString", "builds a unicode string, the usual device name path", 1},
    {"ExAllocatePool", "allocates non paged pool", 1},
    {"ExAllocatePoolWithTag", "allocates non paged pool", 1},
    {"ExFreePoolWithTag", "frees pool memory", 1},
    {"IoCreateDevice", "creates a device object, so the driver is reachable", 1},
    {"IoDeleteDevice", "deletes a device object", 1},
    {"IoCreateSymbolicLink", "publishes a name in the object namespace", 1},
    {"IoDeleteSymbolicLink", "removes a symbolic link", 1},
    {"IofCompleteRequest", "completes an IRP, so the driver handles IOCTLs", 1},
};

const re_kernel_api_t *re_kernel_api_table(size_t *count) {
    if (count)
        *count = sizeof(kKernelApis) / sizeof(kKernelApis[0]);
    return kKernelApis;
}

bool re_kernel_api_lookup(re_str_t sym, const char **why, int *weight) {
    size_t n = 0;
    const re_kernel_api_t *t = re_kernel_api_table(&n);
    for (size_t i = 0; i < n; i++) {
        if (re_str_eq_cstr(sym, t[i].sym)) {
            if (why)
                *why = t[i].why;
            if (weight)
                *weight = t[i].weight;
            return true;
        }
    }
    return false;
}

bool re_triage_has_dynamic_device(const re_strings_t *st, uint64_t *count) {
    uint64_t n = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&st->devices); i++) {
        const re_devname_t *d = RE_VEC_PTR(&st->devices, re_devname_t, i);
        if (d->dynamic)
            n++;
    }
    if (count)
        *count = n;
    return n > 0;
}

static void emit_sections(re_jw_t *w, const re_pe_t *pe) {
    re_jw_key(w, "sections");
    re_jw_arr(w);
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        re_jw_obj(w);
        re_jw_kcstr(w, "name", s->name);
        re_jw_khex(w, "vaddr", s->vaddr, 8);
        re_jw_ku64(w, "vsize", s->vsize);
        re_jw_ku64(w, "raw_size", s->rsize);
        re_jw_khex(w, "raw_ptr", s->rptr, 8);
        re_jw_khex(w, "chars", s->chars, 8);
        re_jw_kf64(w, "entropy", s->entropy);
        re_jw_kbool(w, "packed", s->entropy > 7.0);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

static void emit_imports(re_jw_t *w, const re_pe_t *pe) {
    re_jw_key(w, "imports");
    re_jw_arr(w);
    for (size_t i = 0; i < RE_VEC_LEN(&pe->imports); i++) {
        const re_pe_imp_t *im = RE_VEC_PTR(&pe->imports, re_pe_imp_t, i);
        re_jw_obj(w);
        re_jw_kstr(w, "module", im->dll);
        re_jw_ku64(w, "count", im->n_syms);
        re_jw_key(w, "symbols");
        re_jw_arr(w);
        for (uint32_t k = 0; k < im->n_syms; k++) {
            const re_str_t *s = RE_VEC_PTR(&pe->syms, re_str_t, im->first_sym + k);
            re_jw_str(w, *s);
        }
        re_jw_arr_end(w);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

static void emit_kernel_surface(re_jw_t *w, const re_pe_t *pe) {
    re_jw_key(w, "kernel_surface");
    re_jw_arr(w);
    int score = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&pe->syms); i++) {
        const re_str_t *s = RE_VEC_PTR(&pe->syms, re_str_t, i);
        const char *why = NULL;
        int weight = 0;
        if (!re_kernel_api_lookup(*s, &why, &weight))
            continue;
        score += weight;
        re_jw_obj(w);
        re_jw_kstr(w, "sym", *s);
        re_jw_ku64(w, "weight", (uint64_t)weight);
        re_jw_kcstr(w, "why", why);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
    re_jw_ku64(w, "surface_score", (uint64_t)score);
}

static void emit_devices(re_jw_t *w, const re_strings_t *st) {
    re_jw_key(w, "device_names");
    re_jw_arr(w);
    for (size_t i = 0; i < RE_VEC_LEN(&st->devices); i++) {
        const re_devname_t *d = RE_VEC_PTR(&st->devices, re_devname_t, i);
        re_jw_obj(w);
        re_jw_kstr(w, "name", d->name);
        re_jw_khex(w, "off", d->off, 8);
        re_jw_kbool(w, "wide", d->wide);
        re_jw_kbool(w, "dynamic", d->dynamic);
        re_jw_obj_end(w);
    }
    re_jw_arr_end(w);
}

static void emit_anomalies(re_jw_t *w, re_span_t img, const re_pe_t *pe) {
    uint64_t n = 0;
    re_jw_key(w, "anomalies");
    re_jw_arr(w);
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        if (s->rsize && (uint64_t)s->rptr + s->rsize > img.n) {
            re_jw_cstr(w, "section raw range exceeds the file");
            n++;
        }
        if (s->vsize > 0 && s->rsize > s->vsize * 2u + 0x1000u) {
            re_jw_cstr(w, "section raw much larger than virtual");
            n++;
        }
        if (s->entropy > 7.0) {
            re_jw_cstr(w, "section entropy above 7, possible packing or embedded payload");
            n++;
        }
    }
    re_jw_arr_end(w);
    // Overlay is a sibling key, never an array element. A key/value pair inside
    // an array is not valid JSON and silently corrupts the whole response.
    uint32_t max_end = 0;
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        if (s->rptr + s->rsize > max_end)
            max_end = s->rptr + s->rsize;
    }
    if (max_end && max_end < img.n) {
        re_jw_key(w, "overlay");
        re_jw_obj(w);
        re_jw_ku64(w, "off", max_end);
        re_jw_ku64(w, "size", img.n - max_end);
        re_jw_kbool(w, "security_dir",
                    pe->n_dirs > RE_PE_DD_SECURITY && pe->dd_size[RE_PE_DD_SECURITY] != 0 &&
                        pe->dd_rva[RE_PE_DD_SECURITY] == max_end);
        re_jw_obj_end(w);
        n++;
    } else {
        re_jw_knull(w, "overlay");
    }
    re_jw_ku64(w, "anomaly_count", n);
}

void re_triage_emit(re_jw_t *w, re_span_t img, const re_pe_t *pe, const re_strings_t *st,
                    re_arena_t *a) {
    re_vec_t findings;
    re_rules_eval(img, pe, st, a, &findings);
    (void)a;
    uint8_t md5[RE_MD5_LEN];
    uint8_t sha[RE_SHA256_LEN];
    char hex[RE_SHA256_LEN * 2 + 1];
    re_md5(img.p, img.n, md5);
    re_sha256(img.p, img.n, sha);
    re_hex_encode(hex, sha, RE_SHA256_LEN);
    char md5hex[RE_MD5_LEN * 2 + 1];
    re_hex_encode(md5hex, md5, RE_MD5_LEN);
    re_jw_kcstr(w, "sha256", hex);
    re_jw_kcstr(w, "md5", md5hex);
    re_jw_ku64(w, "size", img.n);
    re_jw_kcstr(w, "arch", re_pe_machine_name(pe->machine));
    re_jw_kbool(w, "pe32plus", pe->pe32plus);
    re_jw_kcstr(w, "subsystem", re_pe_subsystem_name(pe->subsystem));
    re_jw_ku64(w, "subsystem_id", pe->subsystem);
    re_jw_khex(w, "entry_rva", pe->entry_rva, 8);
    re_jw_khex(w, "image_base", pe->image_base, pe->pe32plus ? 16 : 8);
    re_jw_khex(w, "entry_va", pe->image_base + pe->entry_rva, pe->pe32plus ? 16 : 8);
    re_jw_khex(w, "timestamp", pe->timestamp, 8);
    re_jw_ku64(w, "timestamp_unix", pe->timestamp);
    char iso[24];
    re_time_iso((int64_t)pe->timestamp, iso, sizeof(iso));
    re_jw_kcstr(w, "timestamp_iso", iso);
    re_jw_ki64(w, "build_year", re_time_year((int64_t)pe->timestamp));
    re_jw_kbool(w, "is_dll", pe->is_dll);
    re_jw_kbool(w, "force_integrity", pe->signed_hdr);
    re_jw_ku64(w, "section_count", pe->n_sec);
    re_jw_ku64(w, "import_module_count", RE_VEC_LEN(&pe->imports));
    re_jw_ku64(w, "import_symbol_count", RE_VEC_LEN(&pe->syms));
    re_jw_ku64(w, "export_count", RE_VEC_LEN(&pe->exports));
    re_jw_ku64(w, "string_count", RE_VEC_LEN(&st->hits));
    re_jw_ku64(w, "device_name_count", RE_VEC_LEN(&st->devices));
    if (st->pdb.n)
        re_jw_kstr(w, "pdb", st->pdb);
    else
        re_jw_knull(w, "pdb");
    uint64_t dyn = 0;
    re_jw_kbool(w, "dynamic_device_names", re_triage_has_dynamic_device(st, &dyn));
    re_jw_ku64(w, "dynamic_device_count", dyn);
    emit_sections(w, pe);
    emit_imports(w, pe);
    emit_kernel_surface(w, pe);
    emit_devices(w, st);
    emit_anomalies(w, img, pe);
    re_rules_emit(w, &findings, false);
}
