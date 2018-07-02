// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>

//
// Enclave implementation of the standard Unix sbrk() system call.
//
// This function provides an enclave equivalent to the sbrk() system call.
// It increments the current end of the heap by **increment** bytes. Calling
// oe_sbrk() with an increment of 0, returns the current end of the heap.
//
// @param increment Number of bytes to increment the heap end by.
//
// @returns The old end of the heap (before the increment) or (void*)-1 if
// there are less than **increment** bytes left on the heap.
//
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
