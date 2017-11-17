#include "../common/heap.c"
#include <openenclave/bits/globals.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

static OE_Heap __oe_heap = OE_HEAP_INITIALIZER;
static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

/* Initialize the __oe_heap object on he first call */
OE_INLINE void _Init(void)
{
    if (__oe_heap.initialized == false)
    {
        OE_SpinLock(&_lock);
        {
            if (__oe_heap.initialized == false)
            {
                OE_HeapInit(
                    &__oe_heap, 
                    (uintptr_t)__OE_GetHeapBase(),
                    __OE_GetHeapSize());
            }
        }
        OE_SpinUnlock(&_lock);
    }
}

/* Implementation of standard brk() function */
int OE_Brk(uintptr_t addr)
{
    int rc;

    _Init();

    OE_SpinLock(&_lock);
    rc = OE_HeapBrk(&__oe_heap, addr);
    OE_SpinUnlock(&_lock);

    return rc;
}

/* Implementation of standard sbrk() function */
void* OE_Sbrk(ptrdiff_t increment)
{
    void* ptr;

    _Init();

    OE_SpinLock(&_lock);
    ptr = OE_HeapSbrk(&__oe_heap, increment);
    OE_SpinUnlock(&_lock);

    return ptr;
}
