// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>

#ifdef OE_USE_DEBUG_MALLOC

#include "debugmalloc.h"

#define MALLOC oe_debug_malloc
#define FREE oe_debug_free
#define CALLOC oe_debug_calloc
#define REALLOC oe_debug_realloc
#define POSIX_MEMALIGN oe_debug_posix_memalign
#define MALLOC_USABLE_SIZE oe_debug_malloc_usable_size

#else

#define MALLOC oe_allocator_malloc
#define FREE oe_allocator_free
#define CALLOC oe_allocator_calloc
#define REALLOC oe_allocator_realloc
#define POSIX_MEMALIGN oe_allocator_posix_memalign
#define MALLOC_USABLE_SIZE oe_allocator_malloc_usable_size

#endif

/* If true, disable the debug malloc checking */
bool oe_disable_debug_malloc_check;

static oe_allocation_failure_callback_t _failure_callback;

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    _failure_callback = function;
}

bool oe_use_debug_malloc = true;

bool oe_use_debug_malloc_memset = true;

void* oe_malloc(size_t size)
{
    void* p = NULL;
    if (oe_use_debug_malloc)
    {
        p = MALLOC(size);
    }
    else
    {
        p = oe_allocator_malloc(size);
    }

    if (!p && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void oe_free(void* ptr)
{
    if (oe_use_debug_malloc)
    {
        FREE(ptr);
    }
    else
    {
        oe_allocator_free(ptr);
    }
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = NULL;
    if (oe_use_debug_malloc)
    {
        p = CALLOC(nmemb, size);
    }
    else
    {
        p = oe_allocator_calloc(nmemb, size);
    }

    if (!p && nmemb && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = NULL;
    if (oe_use_debug_malloc)
    {
        p = REALLOC(ptr, size);
    }
    else
    {
        p = oe_allocator_realloc(ptr, size);
    }

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
    int rc = POSIX_MEMALIGN(memptr, alignment, size);

    if (rc != 0 && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

size_t oe_malloc_usable_size(void* ptr)
{
    if (oe_use_debug_malloc)
    {
        return MALLOC_USABLE_SIZE(ptr);
    }
    else
    {
        return oe_allocator_malloc_usable_size(ptr);
    }
}
