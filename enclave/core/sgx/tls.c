// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tls.h>
#include <openenclave/internal/sgx/td.h>

// The per-thread shared memory arena
oe_shared_memory_arena_t* oe_get_shared_memory_arena_tls()
{
    return &oe_sgx_get_td()->arena;
}
