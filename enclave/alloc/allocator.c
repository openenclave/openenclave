// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/thread.h>

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

#define ALIAS(OLD, NEW) extern __typeof(OLD) NEW __attribute__((alias(#OLD)))

OE_WEAK_ALIAS(dlmalloc, oe_allocator_malloc);

OE_WEAK_ALIAS(dlcalloc, oe_allocator_calloc);

OE_WEAK_ALIAS(dlrealloc, oe_allocator_realloc);

OE_WEAK_ALIAS(dlmemalign, oe_allocator_memalign);

OE_WEAK_ALIAS(dlposix_memalign, oe_allocator_posix_memalign);

OE_WEAK_ALIAS(dlfree, oe_allocator_free);

void oe_dlmalloc_allocator_thread_startup(void)
{
}

void oe_dlmalloc_allocator_thread_teardown(void)
{
}

OE_WEAK_ALIAS(
    oe_dlmalloc_allocator_thread_startup,
    oe_allocator_thread_startup);

OE_WEAK_ALIAS(
    oe_dlmalloc_allocator_thread_teardown,
    oe_allocator_thread_teardown);

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

int oe_dlmalloc_allocator_get_stats(oe_malloc_stats_t* stats)
{
    int ret = -1;
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

    ret = 0;

done:
    oe_mutex_unlock(&_mutex);
    return ret;
}

OE_WEAK_ALIAS(oe_dlmalloc_allocator_get_stats, oe_allocator_get_stats);
