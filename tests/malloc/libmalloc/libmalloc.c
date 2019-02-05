// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
#include "libmalloc.h"
// clang-format on

libmalloc_t libmalloc;

void* dlmalloc(size_t size);

void dlfree(void* ptr);

void* dlcalloc(size_t nmemb, size_t size);

void* dlrealloc(void* ptr, size_t size);

int dlposix_memalign(void** memptr, size_t alignment, size_t size);

void* dlmemalign(size_t alignment, size_t size);

void* oe_internal_malloc(size_t size)
{
    libmalloc.malloc_count++;
    return dlmalloc(size);
}

void oe_internal_free(void* ptr)
{
    libmalloc.free_count++;
    return dlfree(ptr);
}

void* oe_internal_calloc(size_t nmemb, size_t size)
{
    libmalloc.calloc_count++;
    return dlcalloc(nmemb, size);
}

void* oe_internal_realloc(void* ptr, size_t size)
{
    libmalloc.realloc_count++;
    return dlrealloc(ptr, size);
}

int oe_internal_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    libmalloc.posix_memalign_count++;
    return dlposix_memalign(memptr, alignment, size);
}

void* oe_internal_memalign(size_t alignment, size_t size)
{
    return dlmemalign(alignment, size);
    libmalloc.memalign_count++;
}

void oe_internal_malloc_thread_startup(void)
{
    for (size_t i = 0; i < libmalloc.num_threads; i++)
    {
        if (libmalloc.threads[i].id == oe_thread_self())
        {
            libmalloc.threads[i].count++;
            return;
        }
    }

    if (libmalloc.num_threads == MAX_THREADS)
    {
        oe_assert("too many threads" == NULL);
        oe_abort();
    }

    libmalloc.threads[libmalloc.num_threads].id = oe_thread_self();
    libmalloc.threads[libmalloc.num_threads].count = 1;
    libmalloc.num_threads++;
}

void oe_internal_malloc_thread_teardown(void)
{
    for (size_t i = 0; i < libmalloc.num_threads; i++)
    {
        if (libmalloc.threads[i].id == oe_thread_self())
        {
            libmalloc.threads[i].count--;
            return;
        }
    }
}
