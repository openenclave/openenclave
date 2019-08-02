// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

void* oe_host_calloc(size_t nmemb, size_t size)
{
    OE_UNUSED(nmemb);
    OE_UNUSED(size);

    return NULL;
}

// Function used by oeedger8r for allocating ocall buffers. This function can be
// optimized by allocating a buffer for making ocalls and pass it in to the
// ecall and making it available for use here.
//
// TODO: These are allocated inside the TA and subsequently marshalled by
//       oe_ocall via libutee. This means that the arguments structure is
//       needlessly copied twice in OP-TEE.
void* oe_allocate_ocall_buffer(size_t size)
{
    return oe_malloc(size);
}

// Function used by oeedger8r for freeing ocall buffers.
void oe_free_ocall_buffer(void* buffer)
{
    oe_free(buffer);
}
