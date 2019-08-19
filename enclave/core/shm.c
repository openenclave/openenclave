// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "shm.h"
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include <string.h>

#define ALIGNMENT sizeof(uint64_t)

// the per-thread shared memory pool
__thread Shared_memory_pool shm = {0};

// the global list of shared memory pools
Shared_memory_pool* _shm_list = NULL;

static oe_spinlock_t _shm_list_lock = OE_SPINLOCK_INITIALIZER;

// default shared memory pool capacity is 1 mb
size_t capacity = 1024 * 1024;

size_t max_capacity = 1 << 30;

void* oe_reserve_shm(size_t capacity);
void oe_unreserve_shm(void* buffer);

bool oe_configure_shm_capacity(size_t cap)
{
    if (cap > max_capacity)
    {
        return false;
    }
    capacity = cap;
    return true;
}

void* oe_shm_malloc(size_t size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (shm.buffer == NULL)
    {
        void* buffer = oe_reserve_shm(capacity);
        if (buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);
        shm.buffer = (uint8_t*)buffer;
        shm.capacity = capacity;
        shm.used = 0;

        // add the newly created pool to the global list
        oe_spin_lock(&_shm_list_lock);
        shm.next = _shm_list;
        _shm_list = &shm;
        oe_spin_unlock(&_shm_list_lock);
    }

    // Round up to the nearest alignment size.
    size_t total_size = oe_round_up_to_multiple(size, ALIGNMENT);

    // check for overflow
    OE_CHECK(total_size < size);

    // check for capacity
    size_t used_after;
    OE_CHECK(oe_safe_add_sizet(shm.used, total_size, &used_after));

    // Ok if the incoming malloc puts us below the capacity.
    if (used_after <= shm.capacity)
    {
        uint8_t* addr = shm.buffer + shm.used;
        shm.used = used_after;
        return addr;
    }
    else
        OE_RAISE(OE_OUT_OF_MEMORY);

done:
    return NULL;
}

void* oe_shm_calloc(size_t size)
{
    void* ptr = oe_shm_malloc(size);
    if (ptr != NULL)
    {
        memset(ptr, 0, size);
    }
    return ptr;
}

void oe_shm_clear()
{
    shm.used = 0;
}

// Free all shared memory pools in the global list
void oe_shm_destroy()
{
    Shared_memory_pool* next = _shm_list;
    while (next != NULL)
    {
        oe_unreserve_shm(next->buffer);
        Shared_memory_pool* current = next;
        next = next->next;
        memset(current, 0, sizeof(shm));
    }
    _shm_list = NULL;
}