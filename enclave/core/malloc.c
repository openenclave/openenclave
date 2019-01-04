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

#define HAVE_MMAP 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_TYPES_H
#define LACKS_TIME_H
#define MORECORE sbrk
#define ABORT oe_abort()
#define USE_DL_PREFIX
#define LACKS_STDLIB_H
#define LACKS_STRING_H
#define USE_LOCKS 1
#define size_t size_t
#define ptrdiff_t ptrdiff_t
#define memset oe_memset
#define memcpy oe_memcpy
#define sbrk oe_sbrk
#define fprintf _dlmalloc_stats_fprintf

typedef struct _FILE FILE;

static int _dlmalloc_stats_fprintf(FILE* stream, const char* format, ...);

#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wparentheses-equality"
#endif

#include "../../3rdparty/dlmalloc/dlmalloc/malloc.c"

#pragma GCC diagnostic pop

/* Choose release mode or debug mode allocation functions */
#if defined(OE_USE_DEBUG_MALLOC)
#define MALLOC oe_debug_malloc
#define CALLOC oe_debug_calloc
#define REALLOC oe_debug_realloc
#define MEMALIGN oe_debug_memalign
#define POSIX_MEMALIGN oe_debug_posix_memalign
#define FREE oe_debug_free
#else
#define MALLOC dlmalloc
#define CALLOC dlcalloc
#define REALLOC dlrealloc
#define MEMALIGN dlmemalign
#define POSIX_MEMALIGN dlposix_memalign
#define FREE dlfree
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

/*
**==============================================================================
**
** oe_get_malloc_stats()
**
** The dlmalloc_stats() function prints malloc statistics to standard error
** as shown below.
**
**     fprintf(stderr, "max system bytes = %10lu\n", (unsigned long)(maxfp));
**     fprintf(stderr, "system bytes     = %10lu\n", (unsigned long)(fp));
**     fprintf(stderr, "in use bytes     = %10lu\n", (unsigned long)(used));
**
** But, it provides no function to obtain these same values programmatically.
** This module captures these values by overriding the fprintf() function in
** the dlmalloc sources included below.
**
**==============================================================================
*/

static oe_malloc_stats_t _malloc_stats;
static size_t _dlmalloc_stats_fprintf_calls;

/* Replacement for fprintf in dlmalloc sources below */
static int _dlmalloc_stats_fprintf(FILE* stream, const char* format, ...)
{
    int ret = 0;
    oe_va_list ap;

    OE_UNUSED(stream);
    oe_va_start(ap, format);

    if (oe_strcmp(format, "max system bytes = %10lu\n") == 0)
    {
        _malloc_stats.peak_system_bytes = oe_va_arg(ap, uint64_t);
        _dlmalloc_stats_fprintf_calls++;
    }
    else if (oe_strcmp(format, "system bytes     = %10lu\n") == 0)
    {
        _malloc_stats.system_bytes = oe_va_arg(ap, uint64_t);
        _dlmalloc_stats_fprintf_calls++;
    }
    else if (oe_strcmp(format, "in use bytes     = %10lu\n") == 0)
    {
        _malloc_stats.in_use_bytes = oe_va_arg(ap, uint64_t);
        _dlmalloc_stats_fprintf_calls++;
        goto done;
    }
    else
    {
        oe_assert("_dlmalloc_stats_fprintf(): panic" == NULL);
    }

    oe_va_end(ap);

done:
    return ret;
}

oe_result_t oe_get_malloc_stats(oe_malloc_stats_t* stats)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_mutex_t _mutex = OE_MUTEX_INITIALIZER;

    if (stats)
        oe_memset(stats, 0, sizeof(oe_malloc_stats_t));

    oe_mutex_lock(&_mutex);

    if (!stats)
        goto done;

    // This function indirectly calls _dlmalloc_stats_fprintf(), which sets
    // fields in the _malloc_stats structure.
    _dlmalloc_stats_fprintf_calls = 0;
    dlmalloc_stats();

    /* This function should have been called three times */
    if (_dlmalloc_stats_fprintf_calls != 3)
        goto done;

    *stats = _malloc_stats;

    result = OE_OK;

done:
    oe_mutex_unlock(&_mutex);
    return result;
}
