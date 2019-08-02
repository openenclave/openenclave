// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

#include "optee_t.h"

void* oe_host_calloc(size_t nmemb, size_t size)
{
    void* retval = NULL;

    size_t total_size;
    if (oe_safe_mul_sizet(nmemb, size, &total_size) != OE_OK)
        return NULL;

    if (oe_calloc_ocall(&retval, nmemb, size) != OE_OK)
        return NULL;

    if (retval && !oe_is_outside_enclave(retval, total_size))
    {
        oe_assert("oe_calloc_ocall() returned non-host memory" == NULL);
        oe_abort();
    }

    return retval;
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
