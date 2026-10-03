// re_gui_model.c - the list and the listing, built from the analysis.
// Module: cli (C11).
// Owns: re_gui_model.h's fill functions.
// Depends: re_gui_model.h, re_code, re_strbuf, re_arena, re_disasm. No screen, no
//           terminal, no input.
#include "cli/screen/re_gui_model.h"

#include "features/code/re_code.h"
#include "utils/text/re_strbuf.h"

void re_gui_funcs_fill(re_gui_funcs_t *l, re_arena_t *a, const re_analysis_t *an) {
    l->n = 0;
    size_t total = RE_VEC_LEN(&an->scan.funcs);
    for (size_t i = 0; i < total && l->n < RE_GUI_LIST_MAX; i++) {
        const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, i);
        re_strbuf_t sb;
        re_strbuf_init(&sb, a);
        re_strbuf_put_hex64(&sb, f->va, 16);
        re_strbuf_putc(&sb, 0);
        size_t n = sb.len < 19u ? sb.len : 19u;
        for (size_t k = 0; k < n; k++)
            l->addr[l->n][k] = sb.p[k];
        l->addr[l->n][n] = '\0';
        re_strbuf_t fb;
        re_strbuf_init(&fb, a);
        re_strbuf_puts(&fb, "sub_");
        re_strbuf_put_hex64(&fb, f->va, 16);
        re_strbuf_putc(&fb, 0);
        const char *nm = (f->name.p && f->name.n) ? f->name.p : fb.p;
        l->name[l->n] = re_arena_strdup(a, nm);
        l->n++;
    }
    l->vis = RE_GUI_LIST_ROWS;
    if (l->vis > l->n)
        l->vis = l->n;
}

void re_gui_funcs_window(size_t sel, const re_gui_funcs_t *l, const char **rows, size_t cap) {
    size_t half = l->vis > 2u ? l->vis / 2u : 0u;
    for (size_t i = 0; i < l->vis && i < cap; i++) {
        size_t idx = (sel >= half ? sel - half : 0u) + i;
        if (l->n && idx >= l->n)
            idx = l->n - 1u;
        rows[i] = l->n ? l->name[idx] : "(no functions)";
    }
}

void re_gui_listing_fill(re_gui_listing_t *ls, re_arena_t *a, const re_analysis_t *an, size_t sel) {
    ls->n = 0;
    ls->base = 0;
    for (size_t i = 0; i < RE_GUI_CODE_MAX; i++)
        re_strbuf_init(&ls->line[i], a);
    if (sel >= RE_VEC_LEN(&an->scan.funcs))
        return;
    const re_func_t *f = RE_VEC_PTR(&an->scan.funcs, re_func_t, sel);
    ls->base = (uint32_t)f->va;
    if (!an->code.dis)
        return;
    uint64_t end = f->va + (f->size ? f->size : 1u);
    for (uint64_t va = f->va; va < end && ls->n < RE_GUI_CODE_MAX;) {
        re_insn_t in;
        if (!re_code_insn(&an->code, va, &in))
            break;
        re_strbuf_clear(&ls->line[ls->n]);
        an->code.dis->render(an->code.dis->ctx, &in, a, &ls->line[ls->n]);
        // A call or a branch is where the flow goes, and it is the one thing worth
        // noticing in a listing a reader has not read yet.
        ls->mark[ls->n] = (uint8_t)(in.is_call || in.is_branch);
        ls->text[ls->n] = ls->line[ls->n].p ? ls->line[ls->n].p : "";
        ls->n++;
        if (!in.size)
            break; // a zero length instruction would loop for ever
        va += in.size;
    }
}
