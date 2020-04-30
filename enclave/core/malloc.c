// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/allocator.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>

static oe_allocation_failure_callback_t _failure_callback;

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    _failure_callback = function;
}

void* oe_malloc(size_t size)
{
    void* p = oe_allocator_malloc(size);

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void oe_free(void* ptr)
{
    oe_allocator_free(ptr);
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = oe_allocator_calloc(nmemb, size);

    if (!p && nmemb && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = oe_allocator_realloc(ptr, size);

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void* oe_memalign(size_t alignment, size_t size)
{
    void* ptr = NULL;

    // The only difference between posix_memalign and the obsolete memalign is
    // that posix_memalign requires alignment to be a multiple of sizeof(void*).
    // Adjust the alignment if needed.
    alignment = oe_round_up_to_multiple(alignment, sizeof(void*));

    oe_posix_memalign(&ptr, alignment, size);
    return ptr;
}

int oe_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc = oe_allocator_posix_memalign(memptr, alignment, size);

    if (rc != 0 && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

size_t oe_malloc_usable_size(void* ptr)
{
    return oe_allocator_malloc_usable_size(ptr);
}
