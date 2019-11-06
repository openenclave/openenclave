// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

// Function used by oeedger8r for allocating ocall buffers. This function can be
// optimized by allocating a buffer for making ocalls and pass it in to the
// ecall and making it available for use here.
void* oe_allocate_ocall_buffer(size_t size)
{
    return oe_host_malloc(size);
}

// Function used by oeedger8r for freeing ocall buffers.
void oe_free_ocall_buffer(void* buffer)
{
    oe_host_free(buffer);
}

void* oe_allocate_arena(size_t capacity)
{
    return oe_host_malloc(capacity);
}

void oe_deallocate_arena(void* buffer)
{
    oe_host_free(buffer);
}
