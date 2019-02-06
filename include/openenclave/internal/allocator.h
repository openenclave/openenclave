// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ALLOCATOR_H
#define _OE_ALLOCATOR_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** This header file defines the plugable allocator interface. The default
** versions of these functions are weakly-typed and included in liboealloc.a.
** To override these functions, either (1) define strongly-typed functions with
** the same names, or (2) replace liboealloc.a.
**
**==============================================================================
*/

typedef struct _oe_allocator_stats
{
    uint64_t peak_system_bytes;
    uint64_t system_bytes;
    uint64_t in_use_bytes;
} oe_allocator_stats_t;

typedef struct _oe_allocator_upcalls
{
    void* (*memset_func)(void* s, int c, size_t n);
    void* (*memcpy_func)(void* dest, const void* src, size_t n);
    int (*strcmp_func)(const char* s1, const char* s2);
    void* (*sbrk_func)(ptrdiff_t increment);
    void (*abort_func)(void);
} oe_allocator_upcalls_t;

void oe_allocator_initialize(oe_allocator_upcalls_t* upcalls);

void oe_allocator_threstartup(void);

void oe_allocator_threteardown(void);

void* oe_allocator_malloc(size_t size);

void* oe_allocator_calloc(size_t nmemb, size_t size);

void* oe_allocator_realloc(void* ptr, size_t size);

void* oe_allocator_memalign(size_t alignment, size_t size);

int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size);

void oe_allocator_free(void* ptr);

int oe_allocator_get_stats(oe_allocator_stats_t* stats);

OE_EXTERNC_END

#endif /* _OE_ALLOCATOR_H */
