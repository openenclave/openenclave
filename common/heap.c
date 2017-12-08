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
** Local utility functions:
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
** _List functions
**
**==============================================================================
*/

/* Insert VAD after PREV in the linked list */
static void _ListInsertAfter(
    OE_Heap* heap,
    OE_VAD* prev,
    OE_VAD* vad)
{
    if (prev)
    {
        vad->prev = prev;
        vad->next = prev->next;

        if (prev->next)
            prev->next->prev = vad;

        prev->next = vad;

        heap->coverage[OE_HEAP_COVERAGE_16] = true;
    }
    else
    {
        vad->prev = NULL;
        vad->next = heap->vad_list;

        if (heap->vad_list)
            heap->vad_list->prev = vad;

        heap->vad_list = vad;

        heap->coverage[OE_HEAP_COVERAGE_17] = true;
    }
}

/* Remove VAD from the doubly-linked list */
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

OE_INLINE void _HeapLock(OE_Heap* heap, bool* locked)
{
    OE_MutexLock(&heap->lock);
    *locked = true;
}

OE_INLINE void _HeapUnlock(OE_Heap* heap, bool* locked)
{
    if (*locked)
    {
        OE_MutexUnlock(&heap->lock);
        *locked = false;
    }
}

static void _HeapClearErr(OE_Heap* heap)
{
    if (heap)
        heap->err[0] = '\0';
}

static void _HeapSetErr(OE_Heap* heap, const char* str)
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

static OE_VAD* _HeapNewVAD(
    OE_Heap* heap,
    uintptr_t addr,
    size_t size,
    int prot,
    int flags)
{
    OE_VAD* vad = NULL;

    if (!(vad = _FreeListGet(heap)))
        goto done;

    vad->addr = addr;
    vad->size = (uint32_t)size;
    vad->prot = (uint16_t)prot;
    vad->flags = (uint16_t)flags;

done:
    return vad;
}

/* Synchronize the MAP value to the address of the first list element */
OE_INLINE void _HeapSyncTop(OE_Heap* heap)
{
    if (heap->vad_list)
        heap->map = heap->vad_list->addr;
    else
        heap->map = heap->end;
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
**             MAP
**
** Search for gaps in the following order:
**     (1) Between HEAD and TAIL
**     (2) Between TAIL and END
**
** Note: one of the following conditions always holds:
**     (1) MAP == HEAD
**     (2) MAP == END
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
                *right = p->next;

                addr = _End(p);
                heap->coverage[OE_HEAP_COVERAGE_13] = true;
                goto done;
            }
        }
    }

    /* No gaps in linked list so obtain memory from mapped memory area */
    {
        uintptr_t start = heap->map - size;

        /* If memory was exceeded (overrun of break value) */
        if (!(heap->brk <= start))
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
** Public interface
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

    _HeapClearErr(heap);

    /* Check for invalid parameters */
    if (!heap || !base || !size)
    {
        _HeapSetErr(heap, "bad parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* BASE must be aligned on a page boundary */
    if (base % OE_PAGE_SIZE)
    {
        _HeapSetErr(heap, "bad base parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* SIZE must be a mulitple of the page size */
    if (size % OE_PAGE_SIZE)
    {
        _HeapSetErr(heap, "bad size parameter");
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
    heap->brk = heap->start;

    /* Set the top of the mapped memory (grows negativey) */
    heap->map = heap->end;

    /* Set pointer to the next available entry in the OE_VAD array */
    heap->next_vad = (OE_VAD*)base;

    /* Set pointer to the end address of the OE_VAD array */
    heap->end_vad = (OE_VAD*)heap->start;

    /* Set the free OE_VAD list to null */
    heap->free_vads = NULL;

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

    heap->coverage[OE_HEAP_COVERAGE_18] = true;

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

    _HeapLock(heap, &locked);

    _HeapClearErr(heap);

    if (!_HeapSane(heap))
        goto done;

    if (increment == 0)
    {
        /* Return the current break value without changing it */
        ptr = (void*)heap->brk;
    }
    else if (increment <= heap->map - heap->brk)
    {
        /* Increment the break value and return the old break value */
        ptr = (void*)heap->brk;
        heap->brk += increment;
    }
    else
    {
        _HeapSetErr(heap, "out of memory");
        goto done;
    }

    if (!_HeapSane(heap))
        goto done;

    result = ptr;

done:
    _HeapUnlock(heap, &locked);
    return result;
}

/* Implementation of standard brk() function */
OE_Result OE_HeapBrk(
    OE_Heap* heap,
    uintptr_t addr)
{
    OE_Result result = OE_FAILURE;
    bool locked = false;

    _HeapLock(heap, &locked);

    _HeapClearErr(heap);

    /* Fail if requested address is not within the break memory area */
    if (addr < heap->start || addr >= heap->map)
    {
        _HeapSetErr(heap, "address is out of range");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Set the break value */
    heap->brk = addr;

    if (!_HeapSane(heap))
        OE_THROW(OE_FAILURE);

    result = OE_OK;

catch:
    _HeapUnlock(heap, &locked);
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

    _HeapLock(heap, &locked);

    _HeapClearErr(heap);

    /* Check for valid heap parameter */
    if (!heap || heap->magic != OE_HEAP_MAGIC)
    {
        _HeapSetErr(heap, "bad parameter");
        goto done;
    }

    if (!_HeapSane(heap))
        goto done;

    /* ADDR must be page aligned */
    if (addr && (uintptr_t)addr % OE_PAGE_SIZE)
    {
        _HeapSetErr(heap, "bad addr parameter");
        goto done;
    }

    /* LENGTH must be non-zero */
    if (length == 0)
    {
        _HeapSetErr(heap, "bad length parameter");
        goto done;
    }

    /* PROT must be (OE_PROT_READ | OE_PROT_WRITE) */
    {
        if (!(prot & OE_PROT_READ))
        {
            _HeapSetErr(heap, "bad prot parameter: need OE_PROT_READ");
            goto done;
        }

        if (!(prot & OE_PROT_WRITE))
        {
            _HeapSetErr(heap, "bad prot parameter: need OE_PROT_WRITE");
            goto done;
        }

        if (prot & OE_PROT_EXEC)
        {
            _HeapSetErr(heap, "bad prot parameter: remove OE_PROT_EXEC");
            goto done;
        }
    }

    /* FLAGS must be (OE_MAP_ANONYMOUS | OE_MAP_PRIVATE) */
    {
        if (!(flags & OE_MAP_ANONYMOUS))
        {
            _HeapSetErr(heap, "bad flags parameter: need OE_MAP_ANONYMOUS");
            goto done;
        }

        if (!(flags & OE_MAP_PRIVATE))
        {
            _HeapSetErr(heap, "bad flags parameter: need OE_MAP_PRIVATE");
            goto done;
        }

        if (flags & OE_MAP_SHARED)
        {
            _HeapSetErr(heap, "bad flags parameter: remove OE_MAP_SHARED");
            goto done;
        }

        if (flags & OE_MAP_FIXED)
        {
            _HeapSetErr(heap, "bad flags parameter: remove OE_MAP_FIXED");
            goto done;
        }
    }

    /* Round LENGTH to multiple of page size */
    length = (length + OE_PAGE_SIZE - 1) / OE_PAGE_SIZE * OE_PAGE_SIZE;

    if (addr)
    {
        /* TODO: implement to support mapping non-zero addresses */
        _HeapSetErr(heap, "bad addr parameter: must be null");
        goto done;
    }
    else
    {
        OE_VAD* left;
        OE_VAD* right;

        /* Find a gap that is big enough */
        if (!(start = _HeapFindGap(heap, length, &left, &right)))
        {
            _HeapSetErr(heap, "out of memory");
            goto done;
        }

        if (left && _End(left) == start)
        {
            /* Coalesce with LEFT neighbor */

            left->size += length;

            /* Coalesce with RIGHT neighbor (and release right neighbor) */
            if (right && (start + length == right->addr))
            {
                _ListRemove(heap, right);
                left->size += right->size;
                _FreeListPut(heap, right);
            }

            heap->coverage[OE_HEAP_COVERAGE_0] = true;
        }
        else if (right && (start + length == right->addr))
        {
            /* Coalesce with RIGHT neighbor */

            right->addr = start;
            right->size += length;
            _HeapSyncTop(heap);

            heap->coverage[OE_HEAP_COVERAGE_1] = true;
        }
        else
        {
            OE_VAD* vad;

            /* Create a new VAD and insert it into the list */

            if (!(vad = _HeapNewVAD(heap, start, length, prot, flags)))
            {
                _HeapSetErr(heap, "unexpected: list insert failed");
                goto done;
            }

            _ListInsertAfter(heap, left, vad);
            _HeapSyncTop(heap);

            heap->coverage[OE_HEAP_COVERAGE_2] = true;
        }
    }

    /* Zero-fill mapped memory */
    MEMSET((void*)start, 0, length);

    if (!_HeapSane(heap))
        goto done;

    result = (void*)start;

done:
    _HeapUnlock(heap, &locked);
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

    _HeapLock(heap, &locked);

    _HeapClearErr(heap);

    /* Reject invaid parameters */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr || !length)
    {
        _HeapSetErr(heap, "bad parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    if (!_HeapSane(heap))
        OE_THROW(OE_INVALID_PARAMETER);

    /* ADDRESS must be aligned on a page boundary */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
    {
        _HeapSetErr(heap, "bad addr parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* LENGTH must be a multiple of the page size */
    if (length % OE_PAGE_SIZE)
    {
        _HeapSetErr(heap, "bad length parameter");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Set start and end pointers for this area */
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = (uintptr_t)addr + length;

    /* Find the VAD that contains this address */
    if (!(vad = _ListFind(heap, start)))
    {
        _HeapSetErr(heap, "address not found");
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Fail if this VAD does not contain the end address */
    if (end > _End(vad))
    {
        _HeapSetErr(heap, "illegal range");
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

        _ListRemove(heap, vad);
        _HeapSyncTop(heap);
        _FreeListPut(heap, vad);
        heap->coverage[OE_HEAP_COVERAGE_3] = true;
    }
    else if (vad->addr == start)
    {
        /* Case2: [uuuu............] */

        vad->addr += length;
        vad->size -= length;
        _HeapSyncTop(heap);
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

        OE_VAD* right;

        /* Create VAD for the excess right portion */
        if (!(right = _HeapNewVAD(
            heap, 
            end, 
            vad_end - end, 
            vad->prot, 
            vad->flags)))
        {
            _HeapSetErr(heap, "out of VADs");
            OE_THROW(OE_FAILURE);
        }

        _ListInsertAfter(heap, vad, right);
        _HeapSyncTop(heap);
        heap->coverage[OE_HEAP_COVERAGE_6] = true;
    }

    /* If scrubbing is enabled, then scrub the unmapped memory */
    if (heap->scrub)
        MEMSET(addr, 0xDD, length);

    if (!_HeapSane(heap))
        OE_THROW(OE_UNEXPECTED);

    result = OE_OK;

catch:
    _HeapUnlock(heap, &locked);
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

    _HeapLock(heap, &locked);

    _HeapClearErr(heap);

    /* Check for valid heap parameter */
    if (!heap || heap->magic != OE_HEAP_MAGIC || !addr)
    {
        _HeapSetErr(heap, "invalid parameter");
        goto done;
    }

    if (!_HeapSane(heap))
        goto done;

    /* ADDR must be page aligned */
    if ((uintptr_t)addr % OE_PAGE_SIZE)
    {
        _HeapSetErr(heap, "bad addr parameter: must be multiple of page size");
        goto done;
    }

    /* OLD_SIZE must be non-zero */
    if (old_size == 0)
    {
        _HeapSetErr(heap, "invalid old_size parameter: must be non-zero");
        goto done;
    }

    /* NEW_SIZE must be non-zero */
    if (new_size == 0)
    {
        _HeapSetErr(heap, "invalid old_size parameter: must be non-zero");
        goto done;
    }

    /* FLAGS must be exactly OE_MREMAP_MAYMOVE) */
    if (flags != OE_MREMAP_MAYMOVE)
    {
        _HeapSetErr(heap, "invalid flags parameter: must be OE_MREMAP_MAYMOVE");
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

    /* Find the VAD containing START */
    if (!(vad = _ListFind(heap, start)))
    {
        _HeapSetErr(heap, "invalid addr parameter: mapping not found");
        goto done;
    }

    /* Verify that the end address is within this VAD */
    if (old_end > _End(vad))
    {
        _HeapSetErr(heap, "invalid range");
        goto done;
    }

    /* If the area is shrinking */
    if (new_size < old_size)
    {
        /* If there are excess bytes on the right of this VAD area */
        if (_End(vad) != old_end)
        {
            OE_VAD* right;

            /* Create VAD for rightward excess */
            if (!(right = _HeapNewVAD(
                heap, 
                old_end,
                _End(vad) - old_end,
                vad->prot, 
                vad->flags)))
            {
                _HeapSetErr(heap, "out of VADs");
                goto done;
            }

            _ListInsertAfter(heap, vad, right);
            _HeapSyncTop(heap);

            heap->coverage[OE_HEAP_COVERAGE_7] = true;
        }

        vad->size = new_end - vad->addr;
        new_addr = addr;
        heap->coverage[OE_HEAP_COVERAGE_8] = true;

        /* If scrubbing is enabled, scrub the unmapped portion */
        if (heap->scrub)
            MEMSET((void*)new_end, 0xDD, old_size - new_size);
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
                _ListRemove(heap, next);
                _HeapSyncTop(heap);
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
                _HeapSetErr(heap, "mapping failed");
                goto done;
            }

            /* Copy over data from old area */
            MEMCPY(addr, (void*)start, old_size);

            /* Ummap the old area */
            if (OE_HeapUnmap(heap, (void*)start, old_size) != 0)
            {
                _HeapSetErr(heap, "unmapping failed");
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
    _HeapUnlock(heap, &locked);
    return result;
}

bool OE_HeapSane(OE_Heap* heap)
{
    bool result = false;

    _HeapClearErr(heap);

    if (!heap)
    {
        _HeapSetErr(heap, "invalid parameter");
        goto done;
    }

    _HeapClearErr(heap);

    /* Check the magic number */
    if (heap->magic != OE_HEAP_MAGIC)
    {
        _HeapSetErr(heap, "bad magic");
        goto done;
    }

    /* Check that the heap is initialized */
    if (!heap->initialized)
    {
        _HeapSetErr(heap, "uninitialized");
        goto done;
    }

    /* Check that the start of the heap is strictly less than the end */
    if (!(heap->start < heap->end))
    {
        _HeapSetErr(heap, "start not less than end");
        goto done;
    }

    if (heap->size != (heap->end - heap->base))
    {
        _HeapSetErr(heap, "invalid size");
        goto done;
    }

    if (!(heap->start <= heap->brk))
    {
        _HeapSetErr(heap, "!(heap->start <= heap->brk)");
        goto done;
    }

    if (!(heap->map <= heap->end))
    {
        _HeapSetErr(heap, "!(heap->map <= heap->end)");
        goto done;
    }

    if (heap->vad_list)
    {
        if (heap->map != heap->vad_list->addr)
        {
            _HeapSetErr(heap, "heap->map != heap->vad_list->addr");
            goto done;
        }
    }
    else
    {
        if (heap->map != heap->end)
        {
            _HeapSetErr(heap, "heap->map != heap->end");
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
                    _HeapSetErr(heap, "unordered VAD list (1)");
                    goto done;
                }

                /* No two elements should be contiguous due to coalescense */
                if (_End(p) == next->addr)
                {
                    _HeapSetErr(heap, "contiguous VAD list elements");
                    goto done;
                }

                if (!(_End(p) <= next->addr))
                {
                    _HeapSetErr(heap, "unordered VAD list (2)");
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
