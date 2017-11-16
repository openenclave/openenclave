#include <openenclave/bits/heap.h>
#include <openenclave/thread.h>
#include <openenclave/bits/search.h>

#ifdef OE_BUILD_UNTRUSTED
#include <stdio.h>
#define OE_ENABLE_DUMP
#define TRACE printf("TRACE: %s(%u)\n", __FILE__, __LINE__)
#else
#define TRACE do { } while (0)
#endif

/* Initialize the heap structure. Caller acquires the lock */
int OE_HeapInit(
    OE_Heap* heap,
    uintptr_t base,
    size_t size)
{
    int rc = -1;

    /* Check bad parameters */
    if (!heap || !base || !size)
        goto done;

    /* BASE must be aligned on a page boundary */
    if (base % OE_PAGE_SIZE)
        goto done;

    /* SIZE must be a mulitple of the page size */
    if (size % OE_PAGE_SIZE)
        goto done;

    /* Calculate the total number of pages */
    size_t num_pages = size / OE_PAGE_SIZE;

    /* Save the base of the heap */
    heap->base = base;

    /* Save the size of the heap */
    heap->size = size;

    /* Set the start of the heap area, which follows the VADs array */
    heap->start = base + (num_pages * sizeof(OE_VAD));

    /* Set the end of the heap area */
    heap->end = base + size;

    /* Set the top of the break memory (grows positively) */
    heap->break_top = heap->start;

    /* Set the top of the mapped memory (grows negativey) */
    heap->mapped_top = heap->end;

    /* Set pointer to the next available entry in the OE_VAD array */
    heap->next_vad = (OE_VAD*)base;

    /* Set pointer to the end address of the OE_VAD array */
    heap->end_vad = (OE_VAD*)heap->start;

    /* Set the free OE_VAD list to null */
    heap->free_vads = NULL;

    /* Set the root of the OE_VAD tree to null */
    heap->vad_tree = NULL;

    /* Set the OE_VAD linked list to null */
    heap->vad_list = NULL;

    /* Initialize the lock field */
    {
        OE_Spinlock dummy = OE_SPINLOCK_INITIALIZER;
        heap->lock = dummy;
    }

    /* Finally, set initialized to true */
    heap->initialized = 1;

    rc = 0;

done:
    return rc;
}

#ifdef OE_ENABLE_DUMP
static void _DumpVAD(const OE_VAD* vad)
{
    printf("    OE_VAD{addr=%lx, size=%u}\n", vad->addr, vad->size);
}
#endif

#ifdef OE_ENABLE_DUMP
static void _DumpTree(const OE_VAD* root)
{
    if (!root)
        return;

    _DumpTree((OE_VAD*)root->tnode.left);
    _DumpVAD(root);
    _DumpTree((OE_VAD*)root->tnode.right);
}
#endif

#ifdef OE_ENABLE_DUMP
void OE_HeapDump(const OE_Heap* h)
{
    const OE_VAD* p;

    uintptr_t base = h->base;

    printf("=== OE_Heap()\n");

    printf("initialized:        %s\n", h->initialized ? "true" : "false");

    printf("size:               %lu\n", h->size);

    printf("num_pages:          %lu\n", (h->end - base) / OE_PAGE_SIZE);

    printf("num_vads:           %lu\n", h->end_vad - h->next_vad);

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
#endif

/* Get a free OE_VAD */
static OE_VAD* _GetVAD(
    OE_Heap* heap)
{
    OE_VAD* vad = NULL;

    /* First try the free list */
    if (heap->free_vads)
    {
        vad = heap->free_vads;
        heap->free_vads = vad->next;
        goto done;
    }

    /* Now try the OE_VAD array */
    if (heap->next_vad != heap->end_vad)
    {
        vad = heap->next_vad++;
        goto done;
    }

done:
    return vad;
}

/* Return a free OE_VAD */
OE_INLINE void _PutVAD(
    OE_Heap* heap,
    OE_VAD* vad)
{
    /* Insert into singly-linked free list as first element */
    vad->next = heap->free_vads;
    heap->free_vads = vad;
}

static OE_VAD* _NewVAD(
    OE_Heap* heap,
    uintptr_t addr, 
    size_t size,
    int prot,
    int flags)
{
    OE_VAD* vad;

    if (!(vad = _GetVAD(heap)))
        return NULL;

    vad->addr = addr;
    vad->size = (uint32_t)size;
    vad->prot = (uint16_t)prot;
    vad->flags = (uint16_t)flags;

    return vad;
}

/* Comparison functions for OE_Tsearch() */
static int _InsertCompare(const void *lhsp, const void *rhsp)
{
    OE_VAD* lhs = (OE_VAD*)lhsp;
    OE_VAD* rhs = (OE_VAD*)rhsp;

    if (lhs->addr < rhs->addr)
        return -1;

    if (lhs->addr > rhs->addr)
        return 1;

    return 0;
}

/* Comparison functions for OE_Tfind() */
static int _FindCompare(const void *keyp, const void *vadp)
{
    OE_VAD* key = (OE_VAD*)keyp;
    OE_VAD* vad = (OE_VAD*)vadp;

    uint64_t klo = key->addr;
    uint64_t khi = key->addr + key->size;

    uint64_t vlo = vad->addr;
    uint64_t vhi = vad->addr + vad->size;

#ifdef OE_ENABLE_DUMP
    printf("_FindCompare(): klo=%016lx khi=%016lx vlo=%016lx vhi=%016lx\n",
        klo, khi, vlo, vhi);
#endif

    /* If the key range fits within the VAD range */ 
    if (klo >= vlo && khi <= vhi)
        return 0;

    /* If key low is below VAD low */
    if (klo < vlo)
        return -1;

    /* If key hight is above VAD high */
    if (khi > vhi)
        return 1;

#ifdef OE_ENABLE_DUMP
    printf("_FindCompare(): unexpected\n");
#endif

    return 0;
}

static void* _Alloc(size_t size, void* data)
{
    /* data is a OE_VAD pointer */
    return data;
}

/* Insert OE_VAD into tree */
static int _TreeInsert(
    OE_Heap* heap,
    OE_VAD* vad)
{
    int rc = -1;
    void* ret;

    vad->tnode.key = vad;
    ret = OE_Tsearch(vad, (void**)&heap->vad_tree, _InsertCompare, _Alloc, vad);

    if (ret != vad)
        goto done;

    rc = 0;

done:
    return rc;
}

/* TODO: optimize by using tree to find the insertion point in O(log n) */
static void _ListInsert(
    OE_Heap* heap,
    OE_VAD* vad)
{
    /* If this is the first list element */
    if (!heap->vad_list)
    {
        heap->vad_list = vad;
        vad->prev = NULL;
        vad->next = NULL;
        return;
    }

    /* Insert into list sorted by address */
    {
        OE_VAD* p;
        OE_VAD* prev = NULL;

        /* Find element prev, such that prev->addr < vad->addr */
        for (p = heap->vad_list; p; p = p->next)
        {
            if (p->addr < vad->addr)
            {
                prev = p;
                break;
            }
        }

        /* Insert after 'prev' if non-null, else insert at head */
        if (prev)
        {
            vad->next = prev->next;
            prev->next = vad;

            vad->prev = prev;

            if (prev->next)
                prev->next->prev = vad;
        }
        else
        {
            vad->next = heap->vad_list;
            vad->prev = NULL;

            if (heap->vad_list)
                heap->vad_list->prev = vad;

            heap->vad_list = vad;
        }
    }
}

static int _Insert(
    OE_Heap* heap,
    OE_VAD* vad)
{
    if (_TreeInsert(heap, vad) != 0)
        return -1;

    _ListInsert(heap, vad);
    return 0;
}

/* TODO: optimize by adding a 'gap' field in the tree to find gaps O(log n) */
static uintptr_t _FindRegion(
    OE_Heap* heap,
    size_t size)
{
    uintptr_t addr = 0;

    /* Search for a gap in the linked list */
    {
        OE_VAD* p;
        OE_VAD* prev = NULL;
            
        /* Visit every element in the linked list */
        for (p = heap->vad_list; p; p = p->next)
        {
            uintptr_t start;
            uintptr_t end;

            if (prev)
            {
                /* Looking for gap between current and previous element */
                start = prev->addr + prev->size;
                end = p->addr;
            }
            else
            {
                /* Looking for gap between head element and mapped top */
                start = heap->mapped_top;
                end = p->addr;
            }

            /* If the gap is big enough */
            if (end - start >= size)
            {
                addr = start;
                goto done;
            }

            prev = p;
        }

        if (prev)
        {
            /* Looking for gap between last element and end of heap */
            uintptr_t start = prev->addr + prev->size;
            uintptr_t end = heap->end;

            /* If the gap is big enough */
            if (end - start >= size)
            {
                addr = start;
                goto done;
            }
        }
    }

    /* No gaps in linked list so obtain memory from mapped memory area */
    {
        uintptr_t start = heap->mapped_top - size;

        /* If memory was exceeded (overrun of break top) */
        if (start < heap->break_top)
            goto done;

        heap->mapped_top = start;
        addr = start;
    }

done:
    return addr;
}

static OE_VAD* _FindVAD(
    OE_Heap* heap,
    uintptr_t addr,
    size_t size)
{

    OE_VAD* vad = NULL;
    OE_VAD key;

    key.tnode.key = &key;
    key.addr = addr;
    key.size = size;

    if (!(vad = (OE_VAD*)OE_Tfind(&key, (void*)&heap->vad_tree, _FindCompare)))
    {
        goto done;
    }

done:
    return vad;
}

void* OE_HeapMap(
    OE_Heap* heap,
    void* address,
    size_t size,
    int prot,
    int flags)
{
    void* result = NULL;
    uintptr_t start = 0;

    /* ATTN: check prot and flags! */

    /* Round size to multiple of the page size */
    size = (size + OE_PAGE_SIZE - 1) / OE_PAGE_SIZE * OE_PAGE_SIZE;

    if (address)
    {
        /* ATTN: implement */
        goto done;
    }
    else
    {
        if (!(start = _FindRegion(heap, size)))
            goto done;
    }

    /* Create OE_VAD for this region and inject it into the tree and list */
    {
        OE_VAD* vad;

        /* Allocate a OE_VAD for this new region */
        if (!(vad = _NewVAD(heap, start, size, prot, flags)))
            goto done;

        /* Insert the OE_VAD into the tree and list */
        if (_Insert(heap, vad) != 0)
            goto done;
    }

    result = (void*)start;

done:
    return result;
}

int OE_HeapUnmap(
    OE_Heap* heap,
    void* address,
    size_t size)
{
    int rc = -1;
    OE_VAD* vad;

    if (!heap || !address || !size)
        goto done;

    /* ADDRESS must be aligned on a page boundary */
    if ((uintptr_t)address % OE_PAGE_SIZE)
        goto done;

    /* Round size to multiple of the page size */
    size = (size + OE_PAGE_SIZE - 1) / OE_PAGE_SIZE * OE_PAGE_SIZE;

    /* Find the VAD that includes this region */
    if (!(vad = _FindVAD(heap, (uintptr_t)address, size)))
        goto done;

#ifdef OE_ENABLE_DUMP
    printf("FOUND: \n");
    _DumpVAD(vad);
#endif

done:
    return rc;
}
