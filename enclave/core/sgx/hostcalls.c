// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/stack_alloc.h>

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

void* oe_host_realloc(void* ptr, size_t size)
{
    oe_realloc_args_t* arg_in = NULL;
    uint64_t arg_out = 0;

    if (!(arg_in =
              (oe_realloc_args_t*)oe_host_calloc(1, sizeof(oe_realloc_args_t))))
        goto done;

    arg_in->ptr = ptr;
    arg_in->size = size;

    if (oe_ocall(
            OE_OCALL_REALLOC,
            (uint64_t)arg_in,
            sizeof(*arg_in),
            true,
            &arg_out,
            sizeof(arg_out)) != OE_OK)
    {
        arg_out = 0;
        goto done;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, size))
        oe_abort();

done:
    oe_host_free(arg_in);
    return (void*)arg_out;
}

void* oe_host_memset(void* ptr, int value, size_t num)
{
    return memset(ptr, value, num);
}
