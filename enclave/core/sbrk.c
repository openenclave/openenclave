// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/thread.h>

#if defined(OE_HEAP_ALLOTTED_PAGE_COUNT)
#define OE_HEAP_ALLOTTED_SIZE (OE_HEAP_ALLOTTED_PAGE_COUNT * OE_PAGE_SIZE)
#define OE_HEAP_END_ADDRESS \
    ((unsigned char*)__oe_get_heap_base() + OE_HEAP_ALLOTTED_SIZE)
#else
#define OE_HEAP_END_ADDRESS ((unsigned char*)__oe_get_heap_end())
#endif /* defined (OE_HEAP_ALLOTTED_PAGE_COUNT) */

void* oe_sbrk(ptrdiff_t increment)
{
    static unsigned char* _heap_next;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    void* ptr = (void*)-1;

    oe_spin_lock(&_lock);
    {
        ptrdiff_t remaining;

        if (!_heap_next)
            _heap_next = (unsigned char*)__oe_get_heap_base();

        remaining = (unsigned char*)OE_HEAP_END_ADDRESS - _heap_next;

        if (increment <= remaining)
        {
            ptr = _heap_next;
            _heap_next += increment;
        }
    }
    oe_spin_unlock(&_lock);

    return ptr;
}
