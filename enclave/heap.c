#include <openenclave/bits/heap.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/utils.h>
#include <openenclave/bits/search.h>

/* Virtual Address Descriptor */
typedef struct _VAD
{
    /* Tree node for AVL tree */
    struct OE_tnode tnode;

    /* Pointer to next VAD on linked list */
    struct _VAD* next;

    /* Pointer to previous VAD on linked list */
    struct _VAD* prev;

    /* Address of this memory region */
    uintptr_t addr;

    /* Length of this memory region */
    uint32_t end;

    /* Protection flags for this region OE_PROT_???? */
    uint16_t prot;

    /* Mapping flags for this region: OE_MAP_???? */
    uint16_t flags;
}
VAD;

OE_STATIC_ASSERT(sizeof(VAD) == 64);

/* Lock for synchronizing access to _heap struct */
OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

/* Heap data structures and fields */
typedef struct Heap
{
    /* Start of heap (immediately aft4er VADs array) */
    uintptr_t start;

    /* End of heap (points to first page after end of heap) */
    uintptr_t end;

    /* Top of break memory partition (grows positively) */
    uintptr_t break_top;

    /* Top of mapped memory partition (grows negatively) */
    uintptr_t mapped_top;

    /* The next available VAD in the VADs array */
    VAD* next_vad;

    /* The end of the VADs array */
    VAD* end_vad;

    /* The VAD free list (singly linked) */
    VAD* free_vads;

    /* Root of VAD AVL tree */
    VAD* vad_tree;

    /* Linked list of VADs (sorted by address and doubly linked) */
    VAD* vad_list;
}
Heap;

static Heap _heap;

/* Initialize the heap structure. Caller acquires the lock */
static void _InitializeHeap(void)
{
    /* Calculate the total number of pages */
    size_t num_pages = (_heap.end - _heap.start) / OE_PAGE_SIZE;

    /* Save the base address of the heap */
    uintptr_t heap_base = (uintptr_t)__OE_GetHeapBase();

    /* Save the end address of the heap */
    uintptr_t heap_end = (uintptr_t)__OE_GetHeapEnd();

    /* Set the start of the heap area, which follows the VADs array */
    _heap.start = heap_base + (num_pages * sizeof(VAD));

    /* Set the end of the heap area */
    _heap.end = heap_end;

    /* Set the top of the break memory (grows positively) */
    _heap.break_top = _heap.start;

    /* Set the top of the mapped memory (grows negativey) */
    _heap.mapped_top = _heap.end;

    /* Set pointer to the next available entry in the VAD array */
    _heap.next_vad = (VAD*)_heap.start;

    /* Set pointer to the end address of the VAD array */
    _heap.end_vad = _heap.next_vad + num_pages;

    /* Set the free VAD list to null */
    _heap.free_vads = NULL;

    /* Set the root of the VAD tree to null */
    _heap.vad_tree = NULL;

    /* Set the VAD linked list to null */
    _heap.vad_list = NULL;
}

/* Get a free VAD */
OE_INLINE VAD* _GetVAD(void)
{
    VAD* vad = NULL;

    /* First try the free list */
    if (_heap.free_vads)
    {
        vad = _heap.free_vads;
        _heap.free_vads = vad->next;
        goto done;
    }

    /* Now try the VAD array */
    if (_heap.next_vad != _heap.end_vad)
    {
        vad = _heap.next_vad++;
        goto done;
    }

done:
    return vad;
}

/* Return a free VAD */
OE_INLINE void _PutVAD(VAD* vad)
{
    /* Insert into free list as first element */
    vad->next = _heap.free_vads;
    _heap.free_vads = vad;
}

static int _Compare(const void *lhsp, const void *rhsp)
{
    VAD* lhs = (VAD*)lhsp;
    VAD* rhs = (VAD*)rhsp;

    if (lhs->addr < rhs->addr)
        return -1;

    if (lhs->addr > rhs->addr)
        return 1;

    return 0;
}

static void* _malloc_result;

static void* _Malloc(size_t size)
{
    return _malloc_result;
}

/* Insert VAD into tree */
OE_INLINE int _TreeInsert(VAD* vad)
{
    int rc = -1;
    void* ret;

    vad->tnode.key = vad;
    _malloc_result = vad;
    ret = OE_tsearch(vad, (void**)&_heap.vad_tree, _Compare, _Malloc);
    _malloc_result = NULL;

    if (ret != vad)
        goto done;

    rc = 0;

done:
    return rc;
}

OE_INLINE void _ListInsert(VAD* vad)
{
    /* If this is the first list element */
    if (!_heap.vad_list)
    {
        _heap.vad_list = vad;
        vad->prev = NULL;
        vad->next = NULL;
    }

    /* Insert into list sorted by address */
    {
        VAD* p;
        VAD* q = NULL;

        /* Find insertion point (q) */
        for (p = _heap.vad_list; p; p = p->next)
        {
            if (p->addr < vad->addr)
            {
                q = p;
                break;
            }
        }

        (void)q;
    }
}

/*
**==============================================================================
**
**
**
**==============================================================================
*/

OE_INLINE uintptr_t _GetPageAddress(size_t index)
{
    return (uintptr_t)(_heap.end - ((index + 1) * OE_PAGE_SIZE));
}

OE_INLINE size_t _GetPageIndex(uintptr_t address)
{
    return (((uintptr_t)_heap.end - address) / OE_PAGE_SIZE) - 1;
}

/*
**==============================================================================
**
** __OE_Sbrk()
**
**==============================================================================
*/

/* Implementation of standard sbrk() function */
void* __OE_Sbrk(
    ptrdiff_t increment)
{
    void* ptr = (void*)-1;

    OE_SpinLock(&_lock);
    {
        /* Initialize file-scope variables */
        if (!_heap.start)
            _InitializeHeap();

        if (increment == 0)
        {
            /* Return the current break value without changing it */
            ptr = (void*)_heap.break_top;
        }
        else if (increment <= _heap.end - _heap.mapped_top)
        {
            /* Increment the break value and return the old break value */
            ptr = (void*)_heap.break_top;
            _heap.break_top += increment;
        }
    }
    OE_SpinUnlock(&_lock);

    return ptr;
}

/* Implementation of standard brk() function */
int __OE_Brk(
    uintptr_t addr)
{
    OE_SpinLock(&_lock);
    {
        /* Initialize file-scope variables */
        if (!_heap.start)
            _InitializeHeap();

        /* Fail if requested address is not within the break memory region */
        if (addr < _heap.start || addr >= _heap.mapped_top)
            return -1;

        /* Set the break value */
        _heap.break_top = addr;
    }
    OE_SpinUnlock(&_lock);

    return addr;
}

int __OE_Madvise(
    void *addr, 
    size_t length, 
    int advice)
{
    /* ATTN: handle MADV_DONTNEED */
    return 0;
}

void *__OE_Mmap(
    void *addr, 
    size_t length, 
    int prot, 
    int flags,
    int fd, 
    off_t offset)
{
    void* ptr = OE_MAP_FAILED;

    /* Check addr parameter */
    if (addr)
        return OE_MAP_FAILED;

    /* Check length parameter */
    if (length == 0)
        return OE_MAP_FAILED;

    /* Check prot parameter */
    {
        if (!(prot & OE_PROT_READ))
            return OE_MAP_FAILED;

        if (!(prot & OE_PROT_WRITE))
            return OE_MAP_FAILED;

        if (prot & OE_PROT_EXEC)
            return OE_MAP_FAILED;
    }

    /* Check flags parameter */
    {
        if (!(flags & OE_MAP_ANONYMOUS))
            return OE_MAP_FAILED;

        if (!(flags & OE_MAP_PRIVATE))
            return OE_MAP_FAILED;
    }

    /* Check fd parameter */
    if (fd != -1)
        return OE_MAP_FAILED;

    /* Check offset parameter */
    if (offset != 0)
        return OE_MAP_FAILED;

#if 0
    /* Calculate the number of required pages */
    size_t rpages = OE_RoundUpToMultiple(length, OE_PAGE_SIZE) / OE_PAGE_SIZE;
#endif

    OE_SpinLock(&_lock);
    {
        /* Initialize file-scope variables */
        if (!_heap.start)
            _InitializeHeap();
    }
    OE_SpinUnlock(&_lock);

    return ptr;
}

void *__OE_Mremap(
    void *old_address, 
    size_t old_size,
    size_t new_size, 
    int flags, 
    ... /* void *new_address */)
{
    return NULL;
}

int __OE_Munmap(
    void *addr, 
    size_t length)
{
    return -1;
}
