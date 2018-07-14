// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define OE_ENABLE_MALLOC_WRAPPERS
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
#define LACKS_ERRNO_H
#define USE_LOCKS 1
#define size_t size_t
#define ptrdiff_t ptrdiff_t
#define memset oe_memset
#define memcpy oe_memcpy
#define sbrk oe_sbrk
#define fprintf _dlmalloc_stats_fprintf

static int _dlmalloc_stats_fprintf(FILE* stream, const char* format, ...);

/* Replacement for sched_yield() in dlmalloc sources below */
static int __sched_yield(void)
{
    __asm__ __volatile__("pause");
    return 0;
}

/* Since Dlmalloc provides no way to override the SPIN_LOCK_YIELD macro,
 * redefine sched_yield() directly. Dlmalloc spins for a given number of
 * times and then calls sched_yield(), attempting to yield to other threads.
 */
#define sched_yield __sched_yield

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#include "../3rdparty/dlmalloc/dlmalloc/malloc.c"

/*
**==============================================================================
**
** Debug allocator for tracking unfreed memory.
**
**==============================================================================
*/

#define MAX_ADDRESSES OE_MALLOC_DUMP_ARGS_MAX_ADDRESSES

typedef struct info info_t;

struct info
{
    /* Maintained on singly linked list */
    info_t* next;

    /* Obtained from oe_backtrace() */
    void* addrs[MAX_ADDRESSES];
    int num_addrs;

    /* User address */
    void* data;

    /* User memory size */
    uint64_t size;
};

static info_t* _head;

static void _insert(info_t* info)
{
    info->next = _head;
    _head = info;
}

static info_t* _remove(void* data)
{
    info_t* prev = NULL;

    for (info_t* p = _head; p; p = p->next)
    {
        if (p->data == data)
        {
            if (prev)
            {
                prev->next = p->next;
            }
            else
            {
                _head = p->next;
            }

            return p;
        }

        prev = p;
    }

    return NULL;
}

static info_t* _find(void* data)
{
    for (info_t* p = _head; p; p = p->next)
    {
        if (p->data == data)
            return p;
    }

    return NULL;
}

static size_t _size()
{
    size_t size = 0;

    for (info_t* p = _head; p; p = p->next)
    {
        size++;
    }

    return size;
}

static void _malloc_dump_ocall(uint64_t size, void* addrs[], int num_addrs)
{
    oe_malloc_dump_args_t* args = NULL;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;
    
    if (!(args = oe_host_malloc(sizeof(oe_malloc_dump_args_t))))
        goto done;

    args->size = size;
    memcpy(args->addrs, addrs, sizeof(void*) * OE_COUNTOF(args->addrs));
    args->num_addrs = num_addrs;

    if (oe_ocall(OE_FUNC_MALLOC_DUMP, (uint64_t)args, NULL, flags) != OE_OK)
        goto done;

done:

    if (args)
        oe_host_free(args);
}

void oe_malloc_dump(void)
{
    printf("=== oe_malloc_dump(): %zu chunks\n", _size());

    for (info_t* p = _head; p; p = p->next)
    {
        _malloc_dump_ocall(p->size, p->addrs, p->num_addrs);
    }
}

OE_ALWAYS_INLINE void* _malloc(size_t size)
{
    void* ptr;
    info_t* info;

    if (!(ptr = dlmalloc(size)))
        return NULL;

    if (!(info = dlmalloc(sizeof(info_t))))
    {
        dlfree(ptr);
        return NULL;
    }

    info->num_addrs = oe_backtrace(info->addrs, MAX_ADDRESSES);
    info->data = ptr;
    info->size = size;
    _insert(info);

    return ptr;
}

OE_ALWAYS_INLINE void _free(void* ptr)
{
    if (ptr)
    {
        info_t* info = _remove(ptr);
        assert(info);
        dlfree(ptr);
        dlfree(info);
    }
}

OE_ALWAYS_INLINE void* _calloc(size_t nmemb, size_t size)
{
    void* ptr;
    info_t* info;

    if (!(ptr = dlcalloc(nmemb, size)))
        return NULL;

    if (!(info = dlmalloc(sizeof(info_t))))
    {
        dlfree(ptr);
        return NULL;
    }

    info->num_addrs = oe_backtrace(info->addrs, MAX_ADDRESSES);
    info->data = ptr;
    info->size = nmemb * size;
    _insert(info);

    return ptr;
}

OE_ALWAYS_INLINE void* _realloc(void* ptr, size_t size)
{
    if (ptr)
    {
        void* new_ptr;
        info_t* info = _find(ptr);
        assert(info);

        if (!(new_ptr = dlrealloc(ptr, size)))
            return NULL;

        info->data = new_ptr;
        info->size = size;

        return new_ptr;
    }
    else
    {
        return _malloc(size);
    }
}

OE_ALWAYS_INLINE int _posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc;
    void* ptr;
    info_t* info;

    if ((rc = dlposix_memalign(&ptr, alignment, size)) != 0)
        return rc;

    if (!(info = dlmalloc(sizeof(info_t))))
    {
        dlfree(ptr);
        return ENOMEM;
    }

    info->num_addrs = oe_backtrace(info->addrs, MAX_ADDRESSES);
    info->data = ptr;
    info->size = size;
    _insert(info);

    return rc;
}

OE_ALWAYS_INLINE void* _memalign(size_t alignment, size_t size)
{
    void* ptr;
    info_t* info;

    if (!(ptr = dlmemalign(alignment, size)))
        return NULL;

    if (!(info = dlmalloc(sizeof(info_t))))
    {
        dlfree(ptr);
        return NULL;
    }

    info->num_addrs = oe_backtrace(info->addrs, MAX_ADDRESSES);
    info->data = ptr;
    info->size = size;
    _insert(info);

    return ptr;
}

/*
**==============================================================================
**
** Use malloc wrappers to support oe_set_allocation_failure_callback() if
** OE_ENABLE_MALLOC_WRAPPERS is defined.
**
**==============================================================================
*/

#if defined(OE_ENABLE_MALLOC_WRAPPERS)

static oe_allocation_failure_callback_t _failureCallback;

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    _failureCallback = function;
}

void* malloc(size_t size)
{
    void* p = _malloc(size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void free(void* ptr)
{
    _free(ptr);
}

void* calloc(size_t nmemb, size_t size)
{
    void* p = _calloc(nmemb, size);

    if (!p && nmemb && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* realloc(void* ptr, size_t size)
{
    void* p = _realloc(ptr, size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc = _posix_memalign(memptr, alignment, size);

    if (rc != 0 && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

void* memalign(size_t alignment, size_t size)
{
    void* p = _memalign(alignment, size);

    if (!p && size)
    {
        errno = ENOMEM;

        if (_failureCallback)
            _failureCallback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

/* Raw forms of allocator functions */
OE_WEAK_ALIAS(dlmalloc, __oe_malloc);
OE_WEAK_ALIAS(dlcalloc, __oe_calloc);
OE_WEAK_ALIAS(dlrealloc, __oe_realloc);
OE_WEAK_ALIAS(dlfree, __oe_free);
OE_WEAK_ALIAS(dlmemalign, __oe_memalign);
OE_WEAK_ALIAS(dlposix_memalign, __oe_posix_memalign);

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

static oe_malloc_stats_t _mallocStats;
static size_t _dlmalloc_stats_fprintf_calls;

/* Replacement for fprintf in dlmalloc sources below */
static int _dlmalloc_stats_fprintf(FILE* stream, const char* format, ...)
{
    int ret = 0;
    va_list ap;

    va_start(ap, format);

    if (strcmp(format, "max system bytes = %10lu\n") == 0)
    {
        _mallocStats.peakSystemBytes = va_arg(ap, uint64_t);
        _dlmalloc_stats_fprintf_calls++;
    }
    else if (strcmp(format, "system bytes     = %10lu\n") == 0)
    {
        _mallocStats.systemBytes = va_arg(ap, uint64_t);
        _dlmalloc_stats_fprintf_calls++;
    }
    else if (strcmp(format, "in use bytes     = %10lu\n") == 0)
    {
        _mallocStats.inUseBytes = va_arg(ap, uint64_t);
        _dlmalloc_stats_fprintf_calls++;
        goto done;
    }
    else
    {
        /* Redirect any other fprintf() calls to vfprintf() */
        ret = vfprintf(stream, format, ap);
    }

    va_end(ap);

done:
    return ret;
}

oe_result_t oe_get_malloc_stats(oe_malloc_stats_t* stats)
{
    oe_result_t result = OE_UNEXPECTED;
    static oe_mutex_t _mutex = OE_MUTEX_INITIALIZER;

    if (stats)
        memset(stats, 0, sizeof(oe_malloc_stats_t));

    oe_mutex_lock(&_mutex);

    if (!stats)
        goto done;

    // This function indirectly calls _dlmalloc_stats_fprintf(), which sets
    // fields in the _mallocStats structure.
    _dlmalloc_stats_fprintf_calls = 0;
    dlmalloc_stats();

    /* This function should have been called three times */
    if (_dlmalloc_stats_fprintf_calls != 3)
        goto done;

    *stats = _mallocStats;

    result = OE_OK;

done:
    oe_mutex_unlock(&_mutex);
    return result;
}

/*
**==============================================================================
**
** Alias dlmalloc functions to standard function names if
** OE_ENABLE_MALLOC_WRAPPERS is not defined.
**
**==============================================================================
*/

#else /* !defined(OE_ENABLE_MALLOC_WRAPPERS) */

OE_WEAK_ALIAS(dlmalloc, malloc);
OE_WEAK_ALIAS(dlcalloc, calloc);
OE_WEAK_ALIAS(dlrealloc, realloc);
OE_WEAK_ALIAS(dlfree, free);
OE_WEAK_ALIAS(dlmemalign, memalign);
OE_WEAK_ALIAS(dlposix_memalign, posix_memalign);

#endif /* !defined(OE_ENABLE_MALLOC_WRAPPERS) */
