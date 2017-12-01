#include "../common/heap.c"
#include <openenclave/bits/globals.h>
#include <openenclave/bits/heap.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

static OE_Heap __oe_heap = OE_HEAP_INITIALIZER;
static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

/* Initialize the __oe_heap object on the first call */
static void _Init(void)
{
    OE_SpinLock(&_lock);

    if (__oe_heap.initialized == false)
    {
        OE_HeapInit(
            &__oe_heap, 
            (uintptr_t)__OE_GetHeapBase(),
            __OE_GetHeapSize());
    }

    OE_SpinUnlock(&_lock);
}

int OE_Brk(uintptr_t addr)
{
    if (__oe_heap.initialized == false)
        _Init();

    OE_SpinLock(&_lock);
    OE_Result result = OE_HeapBrk(&__oe_heap, addr);
    OE_SpinUnlock(&_lock);

    return result == OE_OK ? 0 : -1;
}

/*
** Enclave implementation of the standard Unix sbrk() system call.
**
** This function provides an enclave equivalent to the sbrk() system call.
** It increments the current end of the heap by **increment** bytes. Calling
** OE_Sbrk() with an increment of 0, returns the current end of the heap.
**
** @param increment Number of bytes to increment the heap end by.
**
** @returns The old end of the heap (before the increment) or (void*)-1 if
** there are less than **increment** bytes left on the heap.
**
*/
void* OE_Sbrk(ptrdiff_t increment)
{
    void* ptr;

    if (__oe_heap.initialized == false)
        _Init();

    OE_SpinLock(&_lock);
    ptr = OE_HeapSbrk(&__oe_heap, increment);
    OE_SpinUnlock(&_lock);

    /* Map null to expected sbrk() error return type */
    if (!ptr)
        return (void*)-1;

    return ptr;
}

void* OE_Map(
    void* addr,
    size_t length,
    int prot,
    int flags)
{
    if (__oe_heap.initialized == false)
        _Init();

    void* ptr = OE_HeapMap(&__oe_heap, addr, length, prot, flags);

    return ptr ? ptr : (void*)-1;
}

void* OE_Remap(
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags)
{
    if (__oe_heap.initialized == false)
        _Init();

    void* ptr = OE_HeapRemap(&__oe_heap, addr, old_size, new_size, flags);

    return ptr ? ptr : (void*)-1;
}

int OE_Unmap(
    void* address,
    size_t size)
{
    if (__oe_heap.initialized == false)
        _Init();

    OE_Result result = OE_HeapUnmap(&__oe_heap, address, size);

    return result == OE_OK ? 0 : -1;
}
