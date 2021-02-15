// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/advanced/mallinfo.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/syscall/unistd.h>
#include "bigmalloc_t.h"

/* Test a large memory allocation */
oe_result_t test_malloc()
{
    const size_t GIGABYTE = 1024 * 1024 * 1024;
    size_t heap_remaining;
    uint8_t* ptr = NULL;
    extern void* oe_malloc(size_t n);
    extern void oe_free(void* ptr);
    oe_result_t return_value = OE_UNEXPECTED;

    /* Determine how much heap memory remains */
    {
        oe_mallinfo_t info;
        oe_result_t rc = oe_allocator_mallinfo(&info);
        if (rc != OE_OK)
        {
            return_value = rc;
            goto done;
        }
        heap_remaining =
            info.max_total_heap_size - info.current_allocated_heap_size;
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

        if (!(ptr = (uint8_t*)oe_malloc(allocation_size)))
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
        oe_free(ptr);

    return return_value;
}
