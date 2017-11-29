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
# define MEMSET memset
#else
# include <openenclave/enclave.h>
# define U(X)
# define ASSERT OE_Assert
# define printf OE_HostPrintf
# define MEMCPY OE_Memcpy
# define MEMSET OE_Memset
#endif

/*
**==============================================================================
**
** Utility functions:
**
**==============================================================================
*/

OE_INLINE uintptr_t _End(OE_VAD* vad)
{
    return vad->addr + vad->size;
}

/* Get the size of the gap to the right of this VAD */
OE_INLINE size_t _GetRightGap(OE_Heap* heap, OE_VAD* vad)
{
    if (vad->next)
    {
        /* Get size of gap between this VAD and next one */
        return vad->next->addr - _End(vad);
    }
    else
    {
        /* Get size of gap between this VAD and the end of the heap */
        return heap->end - _End(vad);
    }
}

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
    uint64_t hi = _End(vad);

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

static int _HeapSane(
    const OE_Heap* heap)
{
    int rc = 100;

    if (heap->magic != OE_HEAP_MAGIC)
    {
        rc = 1;
        goto done;
    }

    if (!heap->initialized)
    {
        rc = 2;
        goto done;
    }

    if (!(heap->start < heap->end))
    {
        rc = 3;
        goto done;
    }

    if (!(heap->start <= heap->break_top))
    {
        rc = 4;
        goto done;
    }

    if (!(heap->mapped_top <= heap->end))
    {
        rc = 5;
        goto done;
    }

    if (heap->vad_list)
    {
        if (heap->mapped_top != heap->vad_list->addr)
        {
            rc = 6;
            goto done;
        }
    }
    else
    {
        if (heap->mapped_top != heap->end)
        {
            rc = 7;
            goto done;
        }
    }

    /* Verify that the list is sorted */
    {
        OE_VAD* p;

        for (p = heap->vad_list; p; p = p->next)
        {
            OE_VAD* next = p->next;

            if (next)
            {
                if (!(p->addr < next->addr))
                {
                    rc = 8;
                    goto done;
                }

#if 1
                /* No two elements should be contiguous due to coalescense */
                if (_End(p) == next->addr)
                {
printf("p=%lx next=%lx\n", p->addr, next->addr);
                    rc = 9;
                    goto done;
                }
#endif

                if (!(_End(p) <= next->addr))
                {
                    rc = 10;
                    goto done;
                }
            }
        }
    }

    rc = 0;

done:

    if (rc != 0)
        printf("rc=%d\n", rc);

    return rc;
}

static int _HeapInsertVAD(
    OE_Heap* heap,
    OE_VAD* vad)
{
    if (_TreeInsert(heap, vad) != 0)
        return -1;

    _ListInsert(heap, vad);

    /* Update TOP */
    heap->mapped_top = heap->vad_list->addr;

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

    /* Update TOP */
    if (heap->vad_list)
        heap->mapped_top = heap->vad_list->addr;
    else
        heap->mapped_top = heap->end;

    rc = 0;

done:
    return rc;
}

/* 
** Search for a gap (greater than or equal to SIZE) in the VAD list. Set
** LEFT to the leftward neighboring VAD (if any). Set RIGHT to the rightward
** neighboring VAD (if any). Return a pointer to the start of that gap.
**
**                     +----+  +--------+
**                     |    |  |        |
**                     |    v  |        v
**     [........MMMMMMMM....MMMM........MMMMMMMMMMMM........]
**              ^                       ^                   ^
**             HEAD                    TAIL                END
**              ^
**             TOP
**
** Search for gaps in the following order:
**     (1) Between HEAD and TAIL
**     (2) Between TAIL and END
**
** Note: one of the following conditions always holds:
**     (1) TOP == HEAD
**     (2) TOP == END
**
** Optimize to use tree to find gaps (add maxgap field to tree).
**
*/
static uintptr_t _HeapFindGap(
    OE_Heap* heap,
    size_t size,
    OE_VAD** left,
    OE_VAD** right)
{
    uintptr_t addr = 0;

    *left = NULL;
    *right = NULL;

    ASSERT(_HeapSane(heap) == 0);

    /* Look for a gap in the VAD list */
    {
        OE_VAD* p;

        /* Search for gaps between HEAD and TAIL */
        for (p = heap->vad_list; p; p = p->next)
        {
            size_t gap = _GetRightGap(heap, p);

            if (gap >= size)
            {
                *left = p;

                if (gap == size)
                    *right = p->next;

                addr = _End(p);
                goto done;
            }
        }
    }

    /* No gaps in linked list so obtain memory from mapped memory area */
    {
        uintptr_t start = heap->mapped_top - size;

        /* If memory was exceeded (overrun of break top) */
        if (!(heap->break_top <= start))
            goto done;

        if (heap->vad_list)
            *right = heap->vad_list;

        addr = start;
        goto done;
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
    ASSERT(_HeapSane(heap) == 0);
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

    ASSERT(_HeapSane(heap) == 0);
    return ptr;
}

/* Implementation of standard brk() function */
int OE_HeapBrk(
    OE_Heap* heap,
    uintptr_t addr)
{
    /* Fail if requested address is not within the break memory area */
    if (addr < heap->start || addr >= heap->mapped_top)
        return -1;

    /* Set the break value */
    heap->break_top = addr;

    ASSERT(_HeapSane(heap) == 0);
    return 0;
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
        /* TODO: implement to support mapping non-zero addresses */
        goto done;
    }
    else
    {
        OE_VAD* left;
        OE_VAD* right;

        /* Find a gap that is big enough */
        if (!(start = _HeapFindGap(heap, length, &left, &right)))
            goto done;

        if (left)
        {
            /* Coalesce with LEFT neighbor */
            left->size += length;

            /* Coalesce with RIGHT neighbor */
            if (right)
            {
                ASSERT(_HeapRemoveVAD(heap, right) == 0);
                left->size += right->size;
                _FreeListPut(heap, right);
            }
        }
        else if (right)
        {
            /* Coalesce with RIGHT neighbor */
            ASSERT(_HeapRemoveVAD(heap, right) == 0);
            right->addr = start;
            right->size += length;
            ASSERT(_HeapInsertVAD(heap, right) == 0);
        }
        else
        {
            /* Create a new VAD and insert it into the tree and list. */
            ASSERT(_HeapInsertVAD2(heap, start, length, prot, flags) == 0);
        }
    }

    MEMSET((void*)start, 0, length);

    result = (void*)start;

done:

    ASSERT(_HeapSane(heap) == 0);
    return result;
}

int OE_HeapUnmap(
    OE_Heap* heap,
    void* addr,
    size_t length)
{
    int rc = -1;
    OE_VAD* vad = NULL;

    /* Reject invaid parameters */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr || !length)
        goto done;

    /* ADDRESS must be aligned on a page boundary */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
        goto done;

    /* LENGTH must be a multiple of the page size */
    if (length % OE_PAGE_SIZE)
        goto done;

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = (uintptr_t)addr + length;

    /* Find the VAD that contains this address */
    if (!(vad = _TreeFind(heap, start)))
        goto done;

    /* Fail if this VAD does not contain the end address */
    if (end > _End(vad))
        goto done;

    /* If the unapping does not cover the entire area given by the VAD, handle
     * the excess portions. There are 4 cases below, where u's represent 
     * the portion being unmapped.
     *
     *     Case1: [uuuuuuuuuuuuuuuu]
     *     Case2: [uuuu............]
     *     Case3: [............uuuu]
     *     Case4: [....uuuu........]
     */
    {
        /* Case1: [uuuuuuuuuuuuuuuu] */
        if (vad->addr == start && _End(vad) == end)
        {
            ASSERT(_HeapRemoveVAD(heap, vad) == 0);
            _FreeListPut(heap, vad);
            rc = 0;
            goto done;
        }

        /* Case2: [uuuu............] */
        if (vad->addr == start)
        {
            ASSERT(_HeapRemoveVAD(heap, vad) == 0);
            vad->addr += length;
            vad->size -= length;
            ASSERT(_HeapInsertVAD(heap, vad) == 0);
            rc = 0;
            goto done;
        }

        /* Case3: [............uuuu] */
        if (_End(vad) == end)
        {
            vad->size -= length;
            rc = 0;
            goto done;
        }

        /* Case4: [....uuuu........] */
        {
            size_t vad_end = _End(vad);

            /* Adjust the left portion */
            vad->size = start - vad->addr;

            /* Create VAD for the right portion */
            ASSERT(_HeapInsertVAD2(heap, end, vad_end - end, 
                vad->prot, vad->flags) == 0);

            rc = 0;
            goto done;
        }

        ASSERT(0);
    }

    rc = 0;

done:

    ASSERT(_HeapSane(heap) == 0);
    return rc;
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

    ASSERT(_HeapSane(heap) == 0);

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

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t old_end = (uintptr_t)addr + old_size;
    uintptr_t new_end = (uintptr_t)addr + new_size;

    /* Find the VAD for the starting address */
    if (!(vad = _TreeFind(heap, start)))
        goto done;

    /* Verify that the end address is within this VAD */
    if (old_end > _End(vad))
        goto done;

    /* If the area is shrinking */
    if (new_size < old_size)
    {
        /* If there are excess bytes on the right of this VAD area */
        if (_End(vad) != old_end)
        {
            /* Create VAD for rightward excess */
            if (_HeapInsertVAD2(
                heap, 
                old_end,
                _End(vad) - old_end,
                vad->prot, 
                vad->flags) != 0)
            {
                goto done;
            }
        }

        vad->size = new_end - vad->addr;

        result = addr;
        goto done;
    }
    else if (new_size > old_size)
    {
        /* Calculate difference between new and old size */
        size_t delta = new_size - old_size;

        /* If there is room for this area to grow without moving it */
        if (_End(vad) == old_end && _GetRightGap(heap, vad) >= delta)
        {
            vad->size += delta;
            MEMSET((void*)(start + old_size), 0, delta);
            result = addr;

            /* If VAD is now contiguous with next one, coalesce them */
            if (vad->next && _End(vad) == vad->next->addr)
            {
                OE_VAD* next = vad->next;
                vad->size += next->size;
                _HeapRemoveVAD(heap, next);
                _FreeListPut(heap, next);
            }
            goto done;
        }

        /* Map the new area */
        if (!(addr = OE_HeapMap(heap, NULL, new_size, vad->prot, vad->flags)))
            goto done;

        /* Copy over data from old area */
        MEMCPY(addr, (void*)start, old_size);

        /* Ummap the old area */
        if (OE_HeapUnmap(heap, (void*)start, old_size) != 0)
            goto done;

        result = (void*)addr;
    }
    else
    {
        /* Nothing to do since size did not change */
        result = addr;
    }

done:

    ASSERT(_HeapSane(heap) == 0);

    return result;
}
