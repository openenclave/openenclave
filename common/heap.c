#include <openenclave/enclave.h>
#include <openenclave/bits/heap.h>
#include <openenclave/thread.h>
#include <openenclave/bits/utils.h>

#ifdef OE_BUILD_UNTRUSTED
# include <stdio.h>
# include <string.h>
# include <assert.h>
# define ASSERT assert
# define PRINTF printf
# define MEMCPY memcpy
# define MEMSET memset
# define SNPRINTF snprintf
#else
# include <openenclave/enclave.h>
# define ASSERT OE_Assert
# define PRINTF OE_HostPrintf
# define MEMCPY OE_Memcpy
# define MEMSET OE_Memset
# define SNPRINTF OE_Snprintf
#endif

/*
**==============================================================================
**
** Utility functions:
**
**==============================================================================
*/

OE_INLINE void _Lock(OE_Heap* heap, bool* locked)
{
    OE_MutexLock(&heap->lock);
    *locked = true;
}

OE_INLINE void _Unlock(OE_Heap* heap, bool* locked)
{
    if (*locked)
    {
        OE_MutexUnlock(&heap->lock);
        *locked = false;
    }
}

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
** _List functions
**
**==============================================================================
*/

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
        heap->coverage[OE_HEAP_COVERAGE_18] = true;
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
            heap->coverage[OE_HEAP_COVERAGE_16] = true;
        }
        else
        {
            vad->next = heap->vad_list;
            vad->prev = NULL;

            if (heap->vad_list)
                heap->vad_list->prev = vad;

            heap->vad_list = vad;
            heap->coverage[OE_HEAP_COVERAGE_17] = true;
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

/* Find a VAD that contains the given address */
static OE_VAD* _ListFind(
    OE_Heap* heap,
    uintptr_t addr)
{
    OE_VAD* p;

    for (p = heap->vad_list; p; p = p->next)
    {
        if (addr >= p->addr && addr < _End(p))
            return p;
    }

    /* Not found */
    return NULL;
}

/*
**==============================================================================
**
** _Heap functions
**
**==============================================================================
*/

static void _ClearErr(OE_Heap* heap)
{
    if (heap)
        heap->err[0] = '\0';
}

static void _SetErr(OE_Heap* heap, const char* str)
{
    if (heap && str)
        SNPRINTF(heap->err, sizeof(heap->err), "%s", str);
}

OE_INLINE bool _HeapSane(OE_Heap* heap)
{
    if (heap->sanity)
        return OE_HeapSane(heap);

    return true;
}

static int _HeapInsertVAD(
    OE_Heap* heap,
    OE_VAD* vad)
{
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

    /* Remove from doubly-linked list */
    _ListRemove(heap, vad);

    /* Update TOP */
    if (heap->vad_list)
        heap->mapped_top = heap->vad_list->addr;
    else
        heap->mapped_top = heap->end;

    rc = 0;

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

    if (!_HeapSane(heap))
        goto done;

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
                heap->coverage[OE_HEAP_COVERAGE_13] = true;
                goto done;
            }
        }
    }

    /* No gaps in linked list so obtain memory from mapped memory area */
    {
        uintptr_t start = heap->mapped_top - size;

        /* If memory was exceeded (overrun of break top) */
        if (!(heap->break_top <= start))
        {
            heap->coverage[OE_HEAP_COVERAGE_14] = true;
            goto done;
        }

        if (heap->vad_list)
            *right = heap->vad_list;

        addr = start;
        heap->coverage[OE_HEAP_COVERAGE_15] = true;
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
OE_Result OE_HeapInit(
    OE_Heap* heap,
    uintptr_t base,
    size_t size)
{
    OE_Result result = OE_FAILURE;

    _ClearErr(heap);

    /* Check for invalid parameters */
    if (!heap || !base || !size)
    {
        _SetErr(heap, "invalid parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* BASE must be aligned on a page boundary */
    if (base % OE_PAGE_SIZE)
    {
        _SetErr(heap, "invalid base parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* SIZE must be a mulitple of the page size */
    if (size % OE_PAGE_SIZE)
    {
        _SetErr(heap, "invalid size parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Clear the heap object */
    MEMSET(heap, 0, sizeof(OE_Heap));

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

    /* Sanity checks are disabled by default */
    heap->sanity = false;

    /* Set the magic number */
    heap->magic = OE_HEAP_MAGIC;

    /* Initialize the mutex */
    OE_MutexInit(&heap->lock);

    /* Finally, set initialized to true */
    heap->initialized = 1;

    /* Check sanity of heap */
    if (!_HeapSane(heap))
        OE_THROW(OE_UNEXPECTED);

    result = OE_OK;

catch:
    return result;
}

void* OE_HeapSbrk(
    OE_Heap* heap,
    ptrdiff_t increment)
{
    void* result = NULL;
    void* ptr = NULL;
    bool locked = false;

    _Lock(heap, &locked);

    _ClearErr(heap);

    if (!_HeapSane(heap))
        goto done;

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
    else
    {
        _SetErr(heap, "out of memory");
        goto done;
    }

    if (!_HeapSane(heap))
        goto done;

    result = ptr;

done:
    _Unlock(heap, &locked);
    return result;
}

/* Implementation of standard brk() function */
OE_Result OE_HeapBrk(
    OE_Heap* heap,
    uintptr_t addr)
{
    OE_Result result = OE_FAILURE;
    bool locked = false;

    _Lock(heap, &locked);

    _ClearErr(heap);

    /* Fail if requested address is not within the break memory area */
    if (addr < heap->start || addr >= heap->mapped_top)
    {
        _SetErr(heap, "address is out of range");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Set the break value */
    heap->break_top = addr;

    if (!_HeapSane(heap))
        OE_THROW(OE_FAILURE);

    result = OE_OK;

catch:
    _Unlock(heap, &locked);
    return result;
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
    bool locked = false;

    _Lock(heap, &locked);

    _ClearErr(heap);

    /* Check for valid heap parameter */
    if (!heap || heap->magic != OE_HEAP_MAGIC)
    {
        _SetErr(heap, "invalid parameter");
        goto done;
    }

    if (!_HeapSane(heap))
        goto done;

    /* ADDR must be page aligned */
    if (addr && (uintptr_t)addr % OE_PAGE_SIZE)
    {
        _SetErr(heap, "invalid addr parameter");
        goto done;
    }

    /* LENGTH must be non-zero */
    if (length == 0)
    {
        _SetErr(heap, "invalid length parameter");
        goto done;
    }

    /* PROT must be (OE_PROT_READ | OE_PROT_WRITE) */
    {
        if (!(prot & OE_PROT_READ))
        {
            _SetErr(heap, "invalid prot parameter: need OE_PROT_READ");
            goto done;
        }

        if (!(prot & OE_PROT_WRITE))
        {
            _SetErr(heap, "invalid prot parameter: need OE_PROT_WRITE");
            goto done;
        }

        if (prot & OE_PROT_EXEC)
        {
            _SetErr(heap, "invalid prot parameter: remove OE_PROT_EXEC");
            goto done;
        }
    }

    /* FLAGS must be (OE_MAP_ANONYMOUS | OE_MAP_PRIVATE) */
    {
        if (!(flags & OE_MAP_ANONYMOUS))
        {
            _SetErr(heap, "invalid flags parameter: need OE_MAP_ANONYMOUS");
            goto done;
        }

        if (!(flags & OE_MAP_PRIVATE))
        {
            _SetErr(heap, "invalid flags parameter: need OE_MAP_PRIVATE");
            goto done;
        }

        if (flags & OE_MAP_SHARED)
        {
            _SetErr(heap, "invalid flags parameter: remove OE_MAP_SHARED");
            goto done;
        }

        if (flags & OE_MAP_FIXED)
        {
            _SetErr(heap, "invalid flags parameter: remove OE_MAP_FIXED");
            goto done;
        }
    }

    /* Round LENGTH to multiple of page size */
    length = (length + OE_PAGE_SIZE - 1) / OE_PAGE_SIZE * OE_PAGE_SIZE;

    if (addr)
    {
        /* TODO: implement to support mapping non-zero addresses */
        _SetErr(heap, "invalid addr parameter: must be null");
        goto done;
    }
    else
    {
        OE_VAD* left;
        OE_VAD* right;

        /* Find a gap that is big enough */
        if (!(start = _HeapFindGap(heap, length, &left, &right)))
        {
            _SetErr(heap, "out of memory");
            goto done;
        }

        if (left)
        {
            /* Coalesce with LEFT neighbor */
            left->size += length;

            /* Coalesce with RIGHT neighbor */
            if (right)
            {
                if (_HeapRemoveVAD(heap, right) != 0)
                {
                    _SetErr(heap, "unexpected: tree remove failed (1)");
                    goto done;
                }

                left->size += right->size;
                _FreeListPut(heap, right);
            }

            heap->coverage[OE_HEAP_COVERAGE_0] = true;
        }
        else if (right)
        {
            /* Coalesce with RIGHT neighbor */
            if (_HeapRemoveVAD(heap, right) != 0)
            {
                _SetErr(heap, "unexpected: tree remove failed (2)");
                goto done;
            }

            right->addr = start;
            right->size += length;

            if (_HeapInsertVAD(heap, right) != 0)
            {
                _SetErr(heap, "unexpected: tree insertion failed (1)");
                goto done;
            }

            heap->coverage[OE_HEAP_COVERAGE_1] = true;
        }
        else
        {
            /* Create a new VAD and insert it into the tree and list. */
            if (_HeapInsertVAD2(heap, start, length, prot, flags) != 0)
            {
                _SetErr(heap, "unexpected: tree insertion failed (2)");
                goto done;
            }

            heap->coverage[OE_HEAP_COVERAGE_2] = true;
        }
    }

    /* Zero-fill mapped memory */
    MEMSET((void*)start, 0, length);

    if (!_HeapSane(heap))
        goto done;

    result = (void*)start;

done:
    _Unlock(heap, &locked);
    return result;
}

OE_Result OE_HeapUnmap(
    OE_Heap* heap,
    void* addr,
    size_t length)
{
    OE_Result result = OE_FAILURE;
    OE_VAD* vad = NULL;
    bool locked = false;

    _Lock(heap, &locked);

    _ClearErr(heap);

    /* Reject invaid parameters */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr || !length)
    {
        _SetErr(heap, "invalid parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    if (!_HeapSane(heap))
        OE_THROW(OE_INVALID_PARAMETER);

    /* ADDRESS must be aligned on a page boundary */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
    {
        _SetErr(heap, "invalid addr parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* LENGTH must be a multiple of the page size */
    if (length % OE_PAGE_SIZE)
    {
        _SetErr(heap, "invalid length parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = (uintptr_t)addr + length;

    /* Find the VAD that contains this address */
    if (!(vad = _ListFind(heap, start)))
    {
        _SetErr(heap, "address not found");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Fail if this VAD does not contain the end address */
    if (end > _End(vad))
    {
        _SetErr(heap, "invalid range");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* If the unapping does not cover the entire area given by the VAD, handle
     * the excess portions. There are 4 cases below, where u's represent 
     * the portion being unmapped.
     *
     *     Case1: [uuuuuuuuuuuuuuuu]
     *     Case2: [uuuu............]
     *     Case3: [............uuuu]
     *     Case4: [....uuuu........]
     */
    if (vad->addr == start && _End(vad) == end)
    {
        /* Case1: [uuuuuuuuuuuuuuuu] */

        if (_HeapRemoveVAD(heap, vad) != 0)
        {
            _SetErr(heap, "failed to remove VAD (1)");
            OE_THROW(OE_FAILURE);
        }

        _FreeListPut(heap, vad);

        heap->coverage[OE_HEAP_COVERAGE_3] = true;
    }
    else if (vad->addr == start)
    {
        /* Case2: [uuuu............] */

        if (_HeapRemoveVAD(heap, vad) != 0)
        {
            _SetErr(heap, "failed to remove VAD (2)");
            OE_THROW(OE_FAILURE);
        }

        vad->addr += length;
        vad->size -= length;

        if (_HeapInsertVAD(heap, vad) != 0)
        {
            _SetErr(heap, "failed to insert VAD (1)");
            OE_THROW(OE_FAILURE);
        }

        heap->coverage[OE_HEAP_COVERAGE_4] = true;
    }
    else if (_End(vad) == end)
    {
        /* Case3: [............uuuu] */

        vad->size -= length;

        heap->coverage[OE_HEAP_COVERAGE_5] = true;
    }
    else
    {
        /* Case4: [....uuuu........] */

        size_t vad_end = _End(vad);

        /* Adjust the left portion */
        vad->size = start - vad->addr;

        /* Create VAD for the right portion */
        if (_HeapInsertVAD2(
            heap, 
            end, 
            vad_end - end, 
            vad->prot, 
            vad->flags) != 0)
        {
            _SetErr(heap, "failed to insert VAD (2)");
            OE_THROW(OE_FAILURE);
        }

        heap->coverage[OE_HEAP_COVERAGE_6] = true;
    }

    /* If scrubbing is enabled, then scrub the unmapped memory */
    if (heap->scrub)
        MEMSET(addr, 0xDD, length);

    if (!_HeapSane(heap))
        OE_THROW(OE_UNEXPECTED);

    result = OE_OK;

catch:
    _Unlock(heap, &locked);
    return result;
}

void* OE_HeapRemap(
    OE_Heap* heap,
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags)
{
    void* new_addr = NULL;
    void* result = NULL;
    OE_VAD* vad = NULL;
    bool locked = false;

    _Lock(heap, &locked);

    _ClearErr(heap);

    /* Check for valid heap parameter */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr)
    {
        _SetErr(heap, "invalid parameter");
        goto done;
    }

    if (!_HeapSane(heap))
        goto done;

    /* ADDR must be page aligned */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
    {
        _SetErr(heap, "invalid addr parameter: must be multiple of page size");
        goto done;
    }

    /* OLD_SIZE must be non-zero */
    if (old_size == 0)
    {
        _SetErr(heap, "invalid old_size parameter: must be non-zero");
        goto done;
    }

    /* NEW_SIZE must be non-zero */
    if (new_size == 0)
    {
        _SetErr(heap, "invalid old_size parameter: must be non-zero");
        goto done;
    }

    /* FLAGS must be exactly OE_MREMAP_MAYMOVE) */
    if (flags != OE_MREMAP_MAYMOVE)
    {
        _SetErr(heap, "invalid flags parameter: must be OE_MREMAP_MAYMOVE");
        goto done;
    }

    /* Round OLD_SIZE to multiple of page size */
    old_size = OE_RoundUpToMultiple(old_size, OE_PAGE_SIZE);

    /* Round NEW_SIZE to multiple of page size */
    new_size = OE_RoundUpToMultiple(new_size, OE_PAGE_SIZE);

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t old_end = (uintptr_t)addr + old_size;
    uintptr_t new_end = (uintptr_t)addr + new_size;

    /* Find the VAD for the starting address */
    if (!(vad = _ListFind(heap, start)))
    {
        _SetErr(heap, "invalid addr parameter: mapping not found");
        goto done;
    }

    /* Verify that the end address is within this VAD */
    if (old_end > _End(vad))
    {
        _SetErr(heap, "invalid range");
        goto done;
    }

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
                _SetErr(heap, "unexpected: tree insert failed (1)");
                goto done;
            }

            heap->coverage[OE_HEAP_COVERAGE_7] = true;
        }

        /* If scrubbing is enabled, scrub the unmapped portion */
        if (heap->scrub)
            MEMSET((void*)new_end, 0xDD, old_size - new_size);

        vad->size = new_end - vad->addr;
        new_addr = addr;
        heap->coverage[OE_HEAP_COVERAGE_8] = true;
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
            new_addr = addr;
            heap->coverage[OE_HEAP_COVERAGE_9] = true;

            /* If VAD is now contiguous with next one, coalesce them */
            if (vad->next && _End(vad) == vad->next->addr)
            {
                OE_VAD* next = vad->next;
                vad->size += next->size;

                if (_HeapRemoveVAD(heap, next) != 0)
                {
                    _SetErr(heap, "failed to remove VAD");
                    goto done;
                }

                _FreeListPut(heap, next);
                heap->coverage[OE_HEAP_COVERAGE_10] = true;
            }
        }
        else
        {
            /* Map the new area */
            if (!(addr = OE_HeapMap(
                heap, 
                NULL, 
                new_size, 
                vad->prot, 
                vad->flags)))
            {
                _SetErr(heap, "mapping failed");
                goto done;
            }

            /* Copy over data from old area */
            MEMCPY(addr, (void*)start, old_size);

            /* Ummap the old area */
            if (OE_HeapUnmap(heap, (void*)start, old_size) != 0)
            {
                _SetErr(heap, "unmapping failed");
                goto done;
            }

            new_addr = (void*)addr;
            heap->coverage[OE_HEAP_COVERAGE_11] = true;
        }
    }
    else
    {
        /* Nothing to do since size did not change */
        heap->coverage[OE_HEAP_COVERAGE_12] = true;
        new_addr = addr;
    }

    if (!_HeapSane(heap))
        goto done;

    result = new_addr;

done:
    _Unlock(heap, &locked);
    return result;
}

bool OE_HeapSane(OE_Heap* heap)
{
    bool result = false;

    _ClearErr(heap);

    if (!heap)
    {
        _SetErr(heap, "invalid parameter");
        goto done;
    }

    _ClearErr(heap);

    /* Check the magic number */
    if (heap->magic != OE_HEAP_MAGIC)
    {
        _SetErr(heap, "bad magic");
        goto done;
    }

    /* Check that the heap is initialized */
    if (!heap->initialized)
    {
        _SetErr(heap, "uninitialized");
        goto done;
    }

    /* Check that the start of the heap is strictly less than the end */
    if (!(heap->start < heap->end))
    {
        _SetErr(heap, "start not less than end");
        goto done;
    }

    if (heap->size != (heap->end - heap->base))
    {
        _SetErr(heap, "invalid size");
        goto done;
    }

    if (!(heap->start <= heap->break_top))
    {
        _SetErr(heap, "!(heap->start <= heap->break_top)");
        goto done;
    }

    if (!(heap->mapped_top <= heap->end))
    {
        _SetErr(heap, "!(heap->mapped_top <= heap->end)");
        goto done;
    }

    if (heap->vad_list)
    {
        if (heap->mapped_top != heap->vad_list->addr)
        {
            _SetErr(heap, "heap->mapped_top != heap->vad_list->addr");
            goto done;
        }
    }
    else
    {
        if (heap->mapped_top != heap->end)
        {
            _SetErr(heap, "heap->mapped_top != heap->end");
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
                    _SetErr(heap, "unordered VAD list (1)");
                    goto done;
                }

                /* No two elements should be contiguous due to coalescense */
                if (_End(p) == next->addr)
                {
                    _SetErr(heap, "contiguous VAD list elements");
                    goto done;
                }

                if (!(_End(p) <= next->addr))
                {
                    _SetErr(heap, "unordered VAD list (2)");
                    goto done;
                }
            }
        }
    }

    result = true;

done:
    return result;
}

void OE_HeapSetSanity(
    OE_Heap* heap,
    bool sanity)
{
    if (heap)
        heap->sanity = sanity;
}
