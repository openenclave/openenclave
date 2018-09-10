// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/globals.h>
#include "../args.h"

/* Test a large memory allocation */
OE_ECALL void test_malloc(void* args_)
{
    args_t* args = (args_t*)args_;
    const size_t GIGABYTE = 1024 * 1024 * 1024;
    size_t heap_remaining;
    uint8_t* ptr = NULL;
    extern void* dlmalloc(size_t n);
    extern void dlfree(void* ptr);

    args->result = OE_UNEXPECTED;

    /* Determine how much heap memory remains */
    {
        const uint8_t* base = (const uint8_t*)__oe_get_heap_base();
        const uint8_t* brk = (const uint8_t*)oe_sbrk(0);
        const uint8_t* end = (const uint8_t*)__oe_get_heap_end();

        /* Sanity checks */
        if (!(base <= brk && brk < end))
        {
            args->result = OE_FAILURE;
            goto done;
        }

        heap_remaining = end - brk;
    }

    /* Verify that at least 15.9 gigabytes of heap memory are available */
    if (!(heap_remaining > (float)(15.9 * GIGABYTE)))
    {
        args->result = OE_FAILURE;
        goto done;
    }

    /* Allocate 99% of remaining heap memory */
    {
        const size_t allocation_size = (size_t)(0.99 * heap_remaining);

        if (!(ptr = (uint8_t*)dlmalloc(allocation_size)))
        {
            args->result = OE_OUT_OF_MEMORY;
            goto done;
        }

        /* Touch first and last page */
        ptr[0] = 0;
        ptr[allocation_size - 1] = 0;
    }

done:

    if (ptr)
        dlfree(ptr);

    args->result = OE_OK;
}
