// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ALLOCATOR_H
#define _ALLOCATOR_H

#include <openenclave/enclave.h>
#include <openenclave/internal/allocator.h>
#include <openenclave/internal/thread.h>

#define MAX_THREADS 1024

typedef struct _allocator
{
    size_t malloc_count;
    size_t free_count;
    size_t calloc_count;
    size_t realloc_count;
    size_t posix_memalign_count;
    size_t memalign_count;
    struct
    {
        oe_thread_t id;
        size_t count;
    } threads[MAX_THREADS];
    size_t num_threads;
} allocator_t;

extern allocator_t allocator;

#define PEAK_SYSTEM_BYTES 0x790e1b26ae9144e6
#define SYSTEM_BYTES 0xc9c746313c2f4689
#define IN_USE_BYTES 0x38bc5d9ad61f4c97

#endif /* _ALLOCATOR_H */
