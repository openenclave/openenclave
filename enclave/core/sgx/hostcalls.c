// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

void* oe_host_calloc(size_t nmemb, size_t size)
{
    size_t total_size;
    if (oe_safe_mul_sizet(nmemb, size, &total_size) != OE_OK)
        return NULL;

    void* ptr = oe_host_malloc(total_size);

    if (ptr)
        oe_memset_s(ptr, nmemb * size, 0, nmemb * size);

    return ptr;
}

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
