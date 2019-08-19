// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SHM_H
#define _OE_SHM_H

#include <stddef.h>

typedef struct _shared_memory_pool
{
    /* Buffer holding the shared memory pool */
    uint8_t* buffer;
    size_t capacity;
    size_t used;
    struct _shared_memory_pool* next;
} Shared_memory_pool;

bool oe_configure_shm_capacity(size_t cap);

void* oe_shm_malloc(size_t size);

void* oe_shm_calloc(size_t size);

void oe_shm_clear();

void oe_shm_destroy();

#endif /* _OE_SHM_H */
