// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stddef.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <unistd.h>

extern uint8_t ta_heap[];
extern const size_t ta_heap_size;

void* sbrk(intptr_t increment)
{
    static unsigned char* _heap_next = 0;
    void* ptr = (void*)-1;

    ptrdiff_t remaining;

    if (!_heap_next)
    {
        _heap_next = (unsigned char*)ta_heap;
    }

    remaining = ((unsigned char*)(ta_heap) + ta_heap_size) - _heap_next;

    if (increment <= remaining)
    {
        ptr = _heap_next;
        _heap_next += increment;
    }

    return ptr;
}
