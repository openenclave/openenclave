// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ARENA_H
#define _OE_ARENA_H

#include <openenclave/bits/types.h>

typedef struct _shared_memory_arena_t
{
    /* Buffer holding the shared memory pool */
    uint8_t* buffer;
    size_t capacity;
    size_t used;
} shared_memory_arena_t;

bool oe_configure_arena_capacity(size_t cap);

void* oe_arena_malloc(size_t size);

void* oe_arena_calloc(size_t num, size_t size);

void oe_arena_free_all();

void oe_teardown_arena();

#endif /* _OE_ARENA_H */
