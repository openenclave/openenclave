#include <stdio.h>
#include <assert.h>
#include <openenclave/bits/heap.h>
#include <openenclave/thread.h>
#include <openenclave/bits/search.h>

static void _DumpVAD(const OE_VAD* vad)
{
    printf("    OE_VAD{addr=%lx, end=%lx size=%u}\n", 
        vad->addr, vad->addr + vad->size, vad->size);
}

static void _DumpTree(const OE_VAD* root)
{
    if (!root)
        return;

    _DumpTree((OE_VAD*)root->tnode.left);
    _DumpVAD(root);
    _DumpTree((OE_VAD*)root->tnode.right);
}

void OE_HeapDump(const OE_Heap* h)
{
    const OE_VAD* p;

    uintptr_t base = h->base;

    printf("=== OE_Heap()\n");

    printf("initialized:        %s\n", h->initialized ? "true" : "false");

    printf("size:               %lu\n", h->size);

    printf("num_pages:          %lu\n", (h->end - base) / OE_PAGE_SIZE);

    printf("num_vads:           %lu\n", h->end_vad - (OE_VAD*)base);

    printf("base:               %016lx (0)\n", base);

    printf("next_vad:           %016lx (%lu)\n", 
        (uintptr_t)h->next_vad, (uintptr_t)h->next_vad - base);

    printf("end_vad:            %016lx (%lu)\n", 
        (uintptr_t)h->end_vad, (uintptr_t)h->end_vad - base);

    printf("start:              %016lx (%lu)\n", h->start, h->start - base);

    printf("break_top:          %016lx (%lu)\n", 
        h->break_top, h->break_top - base);

    printf("mapped_top:         %016lx (%lu)\n", 
        h->mapped_top, h->mapped_top - base);

    printf("end:                %016lx (%lu)\n", h->end, h->end - base);

    {
        printf("free_vads:\n");
        printf("{\n");

        for (p = h->free_vads; p; p = p->next)
            _DumpVAD(p);

        printf("}\n");
    }

    {
        printf("vad_list=\n");
        printf("{\n");

        for (p = h->vad_list; p; p = p->next)
            _DumpVAD(p);

        printf("}\n");
    }
    {
        printf("vad_tree=\n");
        printf("{\n");
        _DumpTree(h->vad_tree);
        printf("}\n");
    }
}
