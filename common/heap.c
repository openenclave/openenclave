#include <openenclave/enclave.h>
#include <openenclave/bits/heap.h>
#include <openenclave/thread.h>
#include <openenclave/bits/search.h>
#include <openenclave/bits/utils.h>

#ifdef OE_BUILD_UNTRUSTED
# include <stdio.h>
# include <string.h>
# include <assert.h>
# define U(X) X
# define ASSERT assert
# define MEMCPY memcpy
#else
# include <openenclave/enclave.h>
# define U(X)
# define ASSERT OE_Assert
# define printf OE_HostPrintf
# define MEMCPY OE_Memcpy
#endif

/*
**==============================================================================
**
** _FreeList functions
**
**==============================================================================
*/

/* Get a VAD from the free list */
static OE_VAD* _FreeListGet(
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

/* Return a free OE_VAD to the free list */
static void _FreeListPut(
    OE_Heap* heap,
    OE_VAD* vad)
{
    /* Clear the VAD */
    vad->addr = 0;
    vad->size = 0;
    vad->prot = 0;
    vad->flags = 0;

    /* Insert into singly-linked free list as first element */
    vad->next = heap->free_vads;
    heap->free_vads = vad;
}

/*
**==============================================================================
**
** _Tree functions
**
**==============================================================================
*/

/* Comparison function to compare to VADs for equality */
static int _TreeCompare(const void *lhsp, const void *rhsp)
{
    OE_VAD* lhs = (OE_VAD*)lhsp;
    OE_VAD* rhs = (OE_VAD*)rhsp;

    if (lhs->addr < rhs->addr)
        return -1;

    if (lhs->addr > rhs->addr)
        return 1;

    return 0;
}

/* Comparison function for finding VAD that contains an address */
static int _TreeRangeCompare(const void *keyp, const void *vadp)
{
    uintptr_t key = *(uintptr_t*)keyp;
    OE_VAD* vad = (OE_VAD*)vadp;

    uint64_t lo = vad->addr;
    uint64_t hi = vad->addr + vad->size;

    if (key >= lo && key < hi)
        return 0;

    return key < lo ? -1 : 1;
}

static void* _TreeAllocNode(size_t size, void* data)
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

    if (!(ret = OE_Tsearch(
        vad, 
        (void**)&heap->vad_tree, 
        _TreeCompare, 
        _TreeAllocNode, 
        vad)))
    {
        goto done;
    }

    rc = 0;

done:
    return rc;
}

static int _TreeRemove(
    OE_Heap* heap,
    OE_VAD* vad)
{
    int rc = -1;

    if (!OE_Tdelete(vad, (void**)&heap->vad_tree, _TreeCompare, NULL))
        goto done;

    rc = 0;

done:
    return rc;
}

static OE_VAD* _TreeFind(
    OE_Heap* heap,
    uintptr_t addr)
{
    return (OE_VAD*)OE_Tfind(&addr, (void**)&heap->vad_tree, _TreeRangeCompare);
}

/*
**==============================================================================
**
** _List functions
**
**==============================================================================
*/

/* TODO: optimize by using tree to find the insertion point in O(log n) */
static void _ListInsert(
    OE_Heap* heap,
    OE_VAD* vad)
{
    /* If the list is empty */
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
        for (p = heap->vad_list; p && p->addr < vad->addr; p = p->next)
            prev = p;

        /* Insert after 'prev' if non-null, else insert at head */
        if (prev)
        {
            vad->next = prev->next;

            if (prev->next)
                prev->next->prev = vad;

            prev->next = vad;
            vad->prev = prev;
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

static void _ListRemove(
    OE_Heap* heap,
    OE_VAD* vad)
{
    /* Remove from doubly-linked list */
    if (vad == heap->vad_list)
    {
        heap->vad_list = vad->next;

        if (vad->next)
            vad->next->prev = NULL;
    }
    else
    {
        if (vad->prev)
            vad->prev->next = vad->next;

        if (vad->next)
            vad->next->prev = vad->prev;
    }
}

/*
**==============================================================================
**
** _Heap functions
**
**==============================================================================
*/

static int _HeapInsertVAD(
    OE_Heap* heap,
    OE_VAD* vad)
{
    if (_TreeInsert(heap, vad) != 0)
        return -1;

    _ListInsert(heap, vad);

    return 0;
}

static int _HeapInsertVAD2(
    OE_Heap* heap,
    uintptr_t addr,
    size_t size,
    int prot,
    int flags)
{
    int rc = -1;
    OE_VAD* vad;

    if (!(vad = _FreeListGet(heap)))
        goto done;

    vad->addr = addr;
    vad->size = (uint32_t)size;
    vad->prot = (uint16_t)prot;
    vad->flags = (uint16_t)flags;

    if (_HeapInsertVAD(heap, vad) != 0)
        goto done;

    rc = 0;

done:
    return rc;
}

static int _HeapRemoveVAD(OE_Heap* heap, OE_VAD* vad)
{
    int rc = -1;

    /* Remove from tree */
    if (_TreeRemove(heap, vad) != 0)
        goto done;

    /* Remove from doubly-linked list */
    _ListRemove(heap, vad);

    rc = 0;

done:
    return rc;
}

/* TODO: optimize by adding a 'gap' field in the tree to find gaps O(log n) */
static uintptr_t _HeapFindRegion(
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

        /* If there was at least one element in the list */
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
        else
        {
            uintptr_t start = heap->mapped_top;
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

/*
**==============================================================================
**
** OE_Heap functions
**
**==============================================================================
*/

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

    /* Round start up to next page multiple */
    heap->start = OE_RoundUpToMultiple(heap->start, OE_PAGE_SIZE);

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

    /* Set the magic number */
    heap->magic = OE_HEAP_MAGIC;

    /* Finally, set initialized to true */
    heap->initialized = 1;

    rc = 0;

done:
    return rc;
}

void* OE_HeapMap(
    OE_Heap* heap,
    void* addr,
    size_t length,
    int prot,
    int flags)
{
    void* result = NULL;
    uintptr_t start = 0;

    /* Check for valid heap parameter */
    if (!heap || heap->magic != OE_HEAP_MAGIC)
        goto done;

    /* ADDR must be page aligned */
    if (addr && (uintptr_t)addr % OE_PAGE_SIZE)
        goto done;

    /* LENGTH must be non-zero */
    if (length == 0)
        goto done;

    /* PROT must be (OE_PROT_READ | OE_PROT_WRITE) */
    {
        if (!(prot & OE_PROT_READ))
            goto done;

        if (!(prot & OE_PROT_WRITE))
            goto done;

        if (prot & OE_PROT_EXEC)
            goto done;
    }

    /* FLAGS must be (OE_MAP_ANONYMOUS | OE_MAP_PRIVATE) */
    {
        if (!(flags & OE_MAP_ANONYMOUS))
            goto done;

        if (!(flags & OE_MAP_PRIVATE))
            goto done;

        if (flags & OE_MAP_SHARED)
            goto done;

        if (flags & OE_MAP_FIXED)
            goto done;
    }

    /* Round LENGTH to multiple of page size */
    length = (length + OE_PAGE_SIZE - 1) / OE_PAGE_SIZE * OE_PAGE_SIZE;

    if (addr)
    {
        /* ATTN: implement */
        goto done;
    }
    else
    {
        /* Find a region that is big enough */
        if (!(start = _HeapFindRegion(heap, length)))
            goto done;
    }

    /* Create a new VAD and insert it into the tree and list. */
    _HeapInsertVAD2(heap, start, length, prot, flags);

    result = (void*)start;

done:

    return result;
}

void* OE_HeapRemap(
    OE_Heap* heap,
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags)
{
    void* result = NULL;
    OE_VAD* vad = NULL;

    /* Check for valid heap parameter */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr)
        goto done;

    /* ADDR must be page aligned */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
        goto done;

    /* OLD_SIZE must be non-zero */
    if (old_size == 0)
        goto done;

    /* NEW_SIZE must be non-zero */
    if (new_size == 0)
        goto done;

    /* FLAGS must be exactly OE_MREMAP_MAYMOVE) */
    if (flags != OE_MREMAP_MAYMOVE)
        goto done;

    /* Round OLD_SIZE to multiple of page size */
    old_size = OE_RoundUpToMultiple(old_size, OE_PAGE_SIZE);

    /* Round NEW_SIZE to multiple of page size */
    new_size = OE_RoundUpToMultiple(new_size, OE_PAGE_SIZE);

    /* Find the VAD for this address to verify that it is a valid mapping */
    if (!(vad = _TreeFind(heap, (uintptr_t)addr)))
        goto done;

    /* If the region is shrinking, just unmap the excess pages */
    if (new_size < old_size)
    {
        if (OE_HeapUnmap(heap, addr + new_size, old_size - new_size) != 0)
            goto done;

        result = addr;
    }
    else if (new_size > old_size)
    {
        /* ATTN: support remapping without moving (if space available) */
        uintptr_t start;

        /* Find a region big enough for the new region */
        if (!(start = _HeapFindRegion(heap, new_size)))
            goto done;

        /* Copy over the new region */
        MEMCPY((void*)start, addr, old_size);

        /* Create a new VAD and insert it into the tree and list. */
        _HeapInsertVAD2(heap, start, new_size, vad->prot, flags);

        /* Remove the old VAD and add it to the free list */
        {
            if (_HeapRemoveVAD(heap, vad) != 0)
                ASSERT("panic" == NULL);

            _FreeListPut(heap, vad);
        }

        result = (void*)start;
    }
    else
    {
        /* Nothing to do (size did not change) */
        result = addr;
    }

done:

    return result;
}

int OE_HeapUnmap(
    OE_Heap* heap,
    void* addr,
    size_t length)
{
    int rc = -1;
    OE_VAD* head = NULL;
    OE_VAD* tail = NULL;
    size_t count = 0;

    /* Reject invaid parameters */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr || !length)
        goto done;

    /* ADDRESS must be aligned on a page boundary */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
        goto done;

    /* LENGTH must be a multiple of the page size */
    if (length % OE_PAGE_SIZE)
        goto done;

    /* Form a singly-linked list of all VADs that overlap this range */
    {
        uintptr_t start = (uintptr_t)addr;
        uintptr_t end = (uintptr_t)addr + length;

        while (start < end)
        {
            OE_VAD* vad;

            if (!(vad = _TreeFind(heap, start)))
                goto done;

            if (_HeapRemoveVAD(heap, vad) != 0)
            {
                ASSERT("panic" == NULL);
            }

            /* If this vad is not contiguous with the last one */
            if (tail && tail->addr + tail->size != vad->addr)
                goto done;

            if (!head)
            {
                /* Insert first element */
                tail = vad;
                head = vad;
                vad->next = NULL;
            }
            else
            {
                /* Insert at end of list */
                vad->next = NULL;
                tail->next = vad;
                tail = vad;
            }

            count++;
            start = vad->addr + vad->size;
        }
    }

    /* If the unapping does not cover the entire area given by the VAD list, 
     * then create VADs for the each of the excess portions. There are 3 cases 
     * below (where U's represent unmapped portions and m's the mapped parts).
     *
     *     Case1: excess to the right:  [UUUUmmmmmmmmmmmm]
     *     Case2: excess to the middle: [mmmmUUUUmmmmmmmm]
     *     Case3: excess to the left:   [mmmmmmmmmmmmUUUU]
     */
    {
        uintptr_t start = (uintptr_t)addr;
        uintptr_t end = (uintptr_t)addr + length;

        /* Return any unused portion to the left */
        if (head->addr < start)
        {
            _HeapInsertVAD2(
                heap, 
                head->addr, 
                start - head->addr,
                head->prot, 
                head->flags);
        }

        /* Return any unused portion to the right */
        if (end < tail->addr + tail->size)
        {
            _HeapInsertVAD2(
                heap, 
                end,
                tail->addr + tail->size - end,
                head->prot, 
                head->flags);
        }
    }

    /* Put all VADs on the free list */
    {
        OE_VAD* p = head;

        while (p)
        {
            OE_VAD* next = p->next;
            _FreeListPut(heap, p);
            p = next;
        }
    }

    rc = 0;

done:

    /* Restore VADs on failure */
    if (rc != 0)
    {
        OE_VAD* p = head;

        while (p)
        {
            OE_VAD* next = p->next;
            _HeapInsertVAD(heap, p);
            p = next;
        }
    }

    return rc;
}

void* OE_HeapSbrk(
    OE_Heap* heap,
    ptrdiff_t increment)
{
    void* ptr = (void*)-1;

    if (increment == 0)
    {
        /* Return the current break value without changing it */
        ptr = (void*)heap->break_top;
    }
    else if (increment <= heap->mapped_top - heap->break_top)
    {
        /* Increment the break value and return the old break value */
        ptr = (void*)heap->break_top;
        heap->break_top += increment;
    }

    return ptr;
}

/* Implementation of standard brk() function */
int OE_HeapBrk(
    OE_Heap* heap,
    uintptr_t addr)
{
    /* Fail if requested address is not within the break memory region */
    if (addr < heap->start || addr >= heap->mapped_top)
        return -1;

    /* Set the break value */
    heap->break_top = addr;

    return 0;
}

