// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <stdlib.h>
#include "debug_malloc_t.h"

void* ptr;

void enc_allocate_memory()
{
    // Allocate memory, but do not free it.
    // This will be tracked as a leak by debug_malloc and enclave termination
    // will fail with OE_MEMORY_LEAK, if it is not freed.
    ptr = malloc(1024);
}

void enc_cleanup_memory()
{
    free(ptr);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    64,   /* NumStackPages */
    1);   /* NumTCS */
