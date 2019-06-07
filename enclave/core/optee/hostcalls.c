// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
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

char* oe_host_strndup(const char* str, size_t n)
{
    oe_strndup_args_t* arg_in;
    size_t arg_in_sz;
    uint64_t arg_out;
    size_t len;

    if (!str)
        return NULL;

    len = oe_strlen(str);

    if (n < len)
        len = n;

    if (len == OE_SIZE_MAX)
        return NULL;

    arg_in_sz = sizeof(oe_strndup_args_t) + len + 1;
    arg_in = (oe_strndup_args_t*)oe_malloc(arg_in_sz);
    if (!arg_in)
        return NULL;

    arg_in->n = len + 1;

    oe_memcpy_s(arg_in->str, len + 1, str, len);
    arg_in->str[len] = '\0';

    if (oe_ocall(
            OE_OCALL_STRNDUP,
            (uint64_t)arg_in,
            arg_in_sz,
            true,
            &arg_out,
            sizeof(arg_out)) != OE_OK)
    {
        arg_out = 0;
        goto done;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, len + 1))
        oe_abort();

done:
    oe_free(arg_in);
    return (void*)arg_out;
}
