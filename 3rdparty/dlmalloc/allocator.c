// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/allocator.h>
#include <openenclave/enclave.h>

#define HAVE_MMAP 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_TYPES_H
#define LACKS_TIME_H
#define MORECORE dlmalloc_sbrk
#define ABORT oe_abort()
#define USE_DL_PREFIX
#define LACKS_STDLIB_H
#define LACKS_STRING_H
#define USE_LOCKS 1
#define fprintf _dlmalloc_stats_fprintf
#define NO_MALLOC_STATS 1

#ifdef __clang__
#pragma GCC diagnostic ignored "-Wparentheses-equality"
#endif

OE_INLINE
int sched_yield(void)
{
#ifdef __x86__
    asm volatile("pause");
#endif
    return 0;
}

void* dlmalloc_sbrk(ptrdiff_t increment);

#include "dlmalloc/malloc.c"

static uint8_t* _heap_start;
static uint8_t* _heap_end;
static uint8_t* _heap_next;
static int _lock = 0;
void* dlmalloc_sbrk(ptrdiff_t increment)
{
    void* ptr = (void*)-1;

    ACQUIRE_LOCK(&_lock);
    {
        ptrdiff_t remaining;

        if (!_heap_next)
            _heap_next = _heap_start;

        remaining = _heap_end - _heap_next;

        if (increment <= remaining)
        {
            ptr = _heap_next;
            _heap_next += increment;
        }
    }
    RELEASE_LOCK(&_lock);

    return ptr;
}

void oe_allocator_init(void* heap_start_address, void* heap_end_address)
{
    _heap_start = heap_start_address;
    _heap_end = heap_end_address;
}

void oe_allocator_cleanup(void)
{
}

void oe_allocator_thread_init(void)
{
}

void oe_allocator_thread_cleanup(void)
{
}

void* oe_allocator_malloc(size_t size)
{
    return dlmalloc(size);
}

void oe_allocator_free(void* ptr)
{
    dlfree(ptr);
}

void* oe_allocator_calloc(size_t nmemb, size_t size)
{
    return dlcalloc(nmemb, size);
}

void* oe_allocator_realloc(void* ptr, size_t size)
{
    return dlrealloc(ptr, size);
}

void* oe_allocator_aligned_alloc(size_t alignment, size_t size)
{
    return dlmemalign(alignment, size);
}

int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return dlposix_memalign(memptr, alignment, size);
}

size_t oe_allocator_malloc_usable_size(void* ptr)
{
    return dlmalloc_usable_size(ptr);
}
