// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tls.h>

static __thread oe_shared_memory_arena_t _arena;

// The per-thread shared memory arena
oe_shared_memory_arena_t* oe_get_shared_memory_arena_tls()
{
    return &_arena;
}
