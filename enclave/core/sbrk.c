// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

void* oe_sbrk(ptrdiff_t increment)
{
    static unsigned char* _heapNext;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    void* ptr = (void*)-1;

    oe_spin_lock(&_lock);
    {
        size_t remaining;

        if (!_heapNext)
            _heapNext = (unsigned char*)__oe_get_heap_base();

        remaining = (unsigned char*)__oe_get_heap_end() - _heapNext;

        if (increment <= remaining)
        {
            ptr = _heapNext;
            _heapNext += increment;
        }
    }
    oe_spin_unlock(&_lock);

    return ptr;
}
