// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "arena.h"
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/common.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>

// The per-thread shared memory arena
static __thread shared_memory_arena_t _arena = {0};

// Default shared memory arena capacity is 1 mb
static size_t _capacity = 1024 * 1024;

static const size_t _max_capacity = 1 << 30;

void* oe_allocate_arena(size_t capacity);
void oe_deallocate_arena(void* buffer);

bool oe_configure_arena_capacity(size_t cap)
{
    if (cap > _max_capacity)
    {
        return false;
    }
    __atomic_store_n(&_capacity, cap, __ATOMIC_SEQ_CST);
    return true;
}

void* oe_arena_malloc(size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t total_size = 0;
    const size_t align = OE_EDGER8R_BUFFER_ALIGNMENT;

    // Create the anera if it hasn't been created.
    if (_arena.buffer == NULL)
    {
        _arena.capacity = __atomic_load_n(&_capacity, __ATOMIC_SEQ_CST);
        void* buffer = oe_allocate_arena(_arena.capacity);
        if (buffer == NULL)
        {
            _arena.capacity = 0;
            return NULL;
        }
        _arena.buffer = (uint8_t*)buffer;
        _arena.used = 0;
    }

    // Round up to the nearest alignment size.
    total_size = oe_round_up_to_multiple(size, align);

    // check for overflow
    if (total_size < size)
        return NULL;

    // check for capacity
    size_t used_after;
    OE_CHECK(oe_safe_add_sizet(_arena.used, total_size, &used_after));

    // Ok if the incoming malloc puts us below the capacity.
    if (used_after <= _arena.capacity)
    {
        uint8_t* addr = _arena.buffer + _arena.used;
        _arena.used = used_after;
        return addr;
    }

done:
    return NULL;
}

void* oe_arena_calloc(size_t num, size_t size)
{
    size_t total = 0;
    if (oe_safe_mul_sizet(num, size, &total) != OE_OK)
        return NULL;

    void* ptr = oe_arena_malloc(total);
    if (ptr != NULL)
    {
        memset(ptr, 0, total);
    }
    return ptr;
}

void oe_arena_free_all()
{
    _arena.used = 0;
}

// Free the arena in the current thread.
void oe_teardown_arena()
{
    if (_arena.buffer != NULL)
        oe_deallocate_arena(_arena.buffer);
    memset(&_arena, 0, sizeof(_arena));
}
