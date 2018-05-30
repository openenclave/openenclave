// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

void* OE_Sbrk(ptrdiff_t increment)
{
    static unsigned char* _heapNext;
    static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;
    void* ptr = (void*)-1;

    OE_SpinLock(&_lock);
    {
        ptrdiff_t remaining;

        if (!_heapNext)
            _heapNext = (unsigned char*)__OE_GetHeapBase();

        remaining = (unsigned char*)__OE_GetHeapEnd() - _heapNext;

        if (increment <= remaining)
        {
            ptr = _heapNext;
            _heapNext += increment;
        }
    }
    OE_SpinUnlock(&_lock);

    return ptr;
}
