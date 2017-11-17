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

/* Implementation of standard sbrk() function */
void* OE_Sbrk(
    ptrdiff_t increment)
{
    void* ptr = (void*)-1;

    _Init();

    OE_SpinLock(&__oe_heap.lock);
    {
        if (increment == 0)
        {
            /* Return the current break value without changing it */
            ptr = (void*)__oe_heap.break_top;
        }
        else if (increment <= __oe_heap.end - __oe_heap.mapped_top)
        {
            /* Increment the break value and return the old break value */
            ptr = (void*)__oe_heap.break_top;
            __oe_heap.break_top += increment;
        }
    }
    OE_SpinUnlock(&__oe_heap.lock);

    return ptr;
}

/* Implementation of standard brk() function */
int OE_Brk(
    uintptr_t addr)
{
    _Init();

    OE_SpinLock(&__oe_heap.lock);
    {
        /* Fail if requested address is not within the break memory region */
        if (addr < __oe_heap.start || addr >= __oe_heap.mapped_top)
            return -1;

        /* Set the break value */
        __oe_heap.break_top = addr;
    }
    OE_SpinUnlock(&__oe_heap.lock);

    return addr;
}
