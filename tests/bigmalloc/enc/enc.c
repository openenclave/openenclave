// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/elibc/unistd.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include "bigmalloc_t.h"

/* Test a large memory allocation */
oe_result_t test_malloc()
{
    const size_t GIGABYTE = 1024 * 1024 * 1024;
    size_t heap_remaining;
    uint8_t* ptr = NULL;
    extern void* dlmalloc(size_t n);
    extern void dlfree(void* ptr);
    oe_result_t return_value = OE_UNEXPECTED;

    /* Determine how much heap memory remains */
    {
        const uint8_t* base = (const uint8_t*)__oe_get_heap_base();
        const uint8_t* brk = (const uint8_t*)oe_sbrk(0);
        const uint8_t* end = (const uint8_t*)__oe_get_heap_end();

        /* Sanity checks */
        if (!(base <= brk && brk < end))
        {
            return_value = OE_FAILURE;
            goto done;
        }

        heap_remaining = (size_t)(end - brk);
    }

    /* Verify that at least 15.9 gigabytes of heap memory are available */
    if (!(heap_remaining > (float)(15.9 * (double)GIGABYTE)))
    {
        return_value = OE_FAILURE;
        goto done;
    }

    /* Allocate 99% of remaining heap memory */
    {
        const size_t allocation_size = (size_t)(0.99 * (double)heap_remaining);

        if (!(ptr = (uint8_t*)dlmalloc(allocation_size)))
        {
            return_value = OE_OUT_OF_MEMORY;
            goto done;
        }

        /* Touch first and last page */
        ptr[0] = 0;
        ptr[allocation_size - 1] = 0;
    }

    return_value = OE_OK;

done:

    if (ptr)
        dlfree(ptr);

    return return_value;
}
