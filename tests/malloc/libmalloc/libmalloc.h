// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBMALLOC_H
#define _LIBMALLOC_H

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#define MAX_THREADS 1024

typedef struct _libmalloc
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
} libmalloc_t;

extern libmalloc_t libmalloc;

#endif /* _LIBMALLOC_H */
