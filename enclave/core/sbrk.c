// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/thread.h>

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

        remaining = (unsigned char*)__oe_get_heap_end() - _heap_next;

        if (increment <= remaining)
        {
            ptr = _heap_next;
            _heap_next += increment;
        }
    }
    oe_spin_unlock(&_lock);

    return ptr;
}
