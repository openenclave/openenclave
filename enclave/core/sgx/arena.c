// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "arena.h"
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/common.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>

// Default shared memory arena capacity is 1 mb
static size_t _capacity = 1024 * 1024;

static const size_t _max_capacity = 1 << 30;

void* oe_allocate_arena(size_t capacity);
void oe_deallocate_arena(void* buffer);

static oe_shared_memory_arena_t* _get_arena()
{
    /* Note: arenas are zero-initialized by td_init() */
    return &oe_sgx_get_td()->arena;
}

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
    oe_shared_memory_arena_t* arena = _get_arena();

    // Create the arena if it hasn't been created.
    if (arena->buffer == NULL)
    {
        arena->capacity = __atomic_load_n(&_capacity, __ATOMIC_SEQ_CST);
        void* buffer = oe_allocate_arena(arena->capacity);
        if (buffer == NULL)
        {
            arena->capacity = 0;
            return NULL;
        }
        arena->buffer = (uint8_t*)buffer;
        arena->used = 0;
    }

    // Round up to the nearest alignment size.
    total_size = oe_round_up_to_multiple(size, align);

    // check for overflow
    if (total_size < size)
        return NULL;

    // check for capacity
    size_t used_after;
    OE_CHECK(oe_safe_add_sizet(arena->used, total_size, &used_after));

    // Ok if the incoming malloc puts us below the capacity.
    if (used_after <= arena->capacity)
    {
        uint8_t* addr = arena->buffer + arena->used;
        arena->used = used_after;
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
    oe_shared_memory_arena_t* arena = _get_arena();
    arena->used = 0;
}

// Free the arena in the current thread.
void oe_teardown_arena()
{
    oe_shared_memory_arena_t* arena = _get_arena();

    if (arena->buffer != NULL)
        oe_deallocate_arena(arena->buffer);
    memset(arena, 0, sizeof(oe_shared_memory_arena_t));
}
