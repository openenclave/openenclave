// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/print.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/corelibc/stdlib.h>
#include "stress_t.h"

static int rcv = 0;

void do_ecall(int arg)
{
    // almost do nothing
    rcv = arg + 1;
}

oe_result_t do_malloc(int memory_size)
{
    extern void* oe_malloc(size_t n);
    extern void oe_free(void* ptr);
    extern void* dlmalloc_sbrk(size_t n);

    // calculate how much heap memory remains
    size_t remaining_heap;
    const uint8_t* start = (const uint8_t*)__oe_get_heap_base();
    const uint8_t* available = (const uint8_t*)dlmalloc_sbrk(0);
    const uint8_t* end = (const uint8_t*)__oe_get_heap_end();
    if (!(start <= available && available < end))
        return OE_FAILURE;
    else
        remaining_heap = (size_t)(end - available);

    // verify if heap memory is enough
    const size_t GB = 1024 * 1024 * 1024;
    if (!(remaining_heap > (float)(15.9 * (double)GB)))
        return OE_FAILURE;

    // allocate memory_size of available heap memory
    uint8_t* ptr = NULL;
    if (!(ptr = (uint8_t*)oe_malloc((size_t)memory_size)))
    {
        oe_free(ptr);
        return OE_OUT_OF_MEMORY;
    }

    return OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    1);   /* TCSCount */
