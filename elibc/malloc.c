// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>
#include <stdlib.h>

void* elibc_malloc(size_t size)
{
    return oe_malloc(size);
}

void elibc_free(void* ptr)
{
    oe_free(ptr);
}

void* elibc_calloc(size_t nmemb, size_t size)
{
    return oe_calloc(nmemb, size);
}

void* elibc_realloc(void* ptr, size_t size)
{
    return oe_realloc(ptr, size);
}

int elibc_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_posix_memalign(memptr, alignment, size);
}

void* elibc_memalign(size_t alignment, size_t size)
{
    return oe_memalign(alignment, size);
}
