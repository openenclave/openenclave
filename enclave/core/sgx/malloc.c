// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include "debugmalloc.h"
#include "dlmalloc/errno.h"
#include "internalmalloc.h"

/* Choose release mode or debug mode allocation functions */
#if defined(OE_USE_DEBUG_MALLOC)
#define MALLOC oe_debug_malloc
#define CALLOC oe_debug_calloc
#define REALLOC oe_debug_realloc
#define MEMALIGN oe_debug_memalign
#define POSIX_MEMALIGN oe_debug_posix_memalign
#define FREE oe_debug_free
#else
#define MALLOC _oe_malloc
#define CALLOC _oe_calloc
#define REALLOC _oe_realloc
#define MEMALIGN _oe_memalign
#define POSIX_MEMALIGN _oe_posix_memalign
#define FREE _oe_free
#endif

static oe_allocation_failure_callback_t _failure_callback;

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    _failure_callback = function;
}

void* oe_malloc(size_t size)
{
    void* p = MALLOC(size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void oe_free(void* ptr)
{
    FREE(ptr);
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = CALLOC(nmemb, size);

    if (!p && nmemb && size)
    {
        errno = ENOMEM;

        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = REALLOC(ptr, size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

int oe_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc = POSIX_MEMALIGN(memptr, alignment, size);

    if (rc != 0 && size)
    {
        errno = ENOMEM;

        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

void* oe_memalign(size_t alignment, size_t size)
{
    void* p = MEMALIGN(alignment, size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}
