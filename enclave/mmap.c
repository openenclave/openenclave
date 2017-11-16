#include <openenclave/bits/globals.h>
#include <openenclave/bits/heap.h>
#include <openenclave/thread.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

extern OE_Heap __oe_heap;

OE_INLINE void _Init(void)
{
    if (__oe_heap.initialized == false)
    {
        OE_SpinLock(&__oe_heap.lock);
        {
            if (__oe_heap.initialized == false)
            {
                OE_HeapInit(
                    &__oe_heap, 
                    (uintptr_t)__OE_GetEnclaveBase(),
                    __OE_GetEnclaveSize());
            }
        }
        OE_SpinUnlock(&__oe_heap.lock);
    }
}

int __OE_Madvise(
    void *addr, 
    size_t length, 
    int advice)
{
    _Init();

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

    _Init();

    /* Check addr parameter */
    if (addr)
    {
        /* ATTN: support this */
        return OE_MAP_FAILED;
    }

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

    OE_SpinLock(&__oe_heap.lock);
    {
        /* Allocate a mapped regions */
        void* start = OE_HeapMap(&__oe_heap, addr, length, prot, flags);

        if (start)
            ptr = start;
    }
    OE_SpinUnlock(&__oe_heap.lock);

    return ptr;
}

void *__OE_Mremap(
    void *old_address, 
    size_t old_size,
    size_t new_size, 
    int flags, 
    ... /* void *new_address */)
{
    _Init();
    return NULL;
}

int __OE_Munmap(
    void *addr, 
    size_t length)
{
    _Init();
    return -1;
}
