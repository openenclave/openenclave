// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "allocator.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/allocator.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>

allocator_t allocator;

void* oe_allocator_malloc(size_t size)
{
    extern void* dlmalloc(size_t size);
    allocator.malloc_count++;
    return dlmalloc(size);
}

void oe_allocator_free(void* ptr)
{
    extern void dlfree(void* ptr);
    allocator.free_count++;
    return dlfree(ptr);
}

void* oe_allocator_calloc(size_t nmemb, size_t size)
{
    extern void* dlcalloc(size_t nmemb, size_t size);
    allocator.calloc_count++;
    return dlcalloc(nmemb, size);
}

void* oe_allocator_realloc(void* ptr, size_t size)
{
    extern void* dlrealloc(void* ptr, size_t size);
    allocator.realloc_count++;
    return dlrealloc(ptr, size);
}

int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    extern int dlposix_memalign(void** memptr, size_t alignment, size_t size);
    allocator.posix_memalign_count++;
    return dlposix_memalign(memptr, alignment, size);
}

void* oe_allocator_memalign(size_t alignment, size_t size)
{
    void* dlmemalign(size_t alignment, size_t size);
    allocator.memalign_count++;
    return dlmemalign(alignment, size);
}

void oe_allocator_thread_startup(void)
{
    for (size_t i = 0; i < allocator.num_threads; i++)
    {
        if (allocator.threads[i].id == oe_thread_self())
        {
            allocator.threads[i].count++;
            return;
        }
    }

    if (allocator.num_threads == MAX_THREADS)
    {
        oe_assert("too many threads" == NULL);
        oe_abort();
    }

    allocator.threads[allocator.num_threads].id = oe_thread_self();
    allocator.threads[allocator.num_threads].count = 1;
    allocator.num_threads++;
}

void oe_allocator_thread_teardown(void)
{
    for (size_t i = 0; i < allocator.num_threads; i++)
    {
        if (allocator.threads[i].id == oe_thread_self())
        {
            allocator.threads[i].count--;
            return;
        }
    }
}

int oe_allocator_get_stats(oe_allocator_stats_t* stats)
{
    stats->peak_system_bytes = PEAK_SYSTEM_BYTES;
    stats->system_bytes = SYSTEM_BYTES;
    stats->in_use_bytes = IN_USE_BYTES;
    return 0;
}
