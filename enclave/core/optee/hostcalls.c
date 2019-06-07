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
    oe_calloc_args_t arg_in;
    uint64_t arg_out = 0;

    arg_in.nmemb = nmemb;
    arg_in.size = size;

    if (oe_ocall(
            OE_OCALL_CALLOC,
            (uint64_t)&arg_in,
            sizeof(arg_in),
            true,
            &arg_out,
            sizeof(arg_out)) != OE_OK)
    {
        return NULL;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, size))
        oe_abort();

    return (void*)arg_out;
}

void* oe_host_realloc(void* ptr, size_t size)
{
    oe_realloc_args_t arg_in;
    uint64_t arg_out = 0;

    arg_in.ptr = ptr;
    arg_in.size = size;

    if (oe_ocall(
            OE_OCALL_REALLOC,
            (uint64_t)&arg_in,
            sizeof(arg_in),
            true,
            &arg_out,
            sizeof(arg_out)) != OE_OK)
    {
        return NULL;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, size))
        oe_abort();

    return (void*)arg_out;
}

void* oe_host_memset(void* ptr, int value, size_t num)
{
    oe_memset_args_t arg_in;
    uint64_t arg_out = 0;

    arg_in.ptr = ptr;
    arg_in.value = value;
    arg_in.num = num;

    if (oe_ocall(
            OE_OCALL_MEMSET,
            (uint64_t)&arg_in,
            sizeof(arg_in),
            true,
            &arg_out,
            sizeof(arg_out)) != OE_OK)
    {
        return NULL;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, num))
        oe_abort();

    return (void*)arg_out;
}
