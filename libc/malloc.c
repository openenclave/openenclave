// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/enclavelibc.h>
#include <stdlib.h>

void* malloc(size_t size)
{
    void* p = oe_malloc(size);

    if (!p && size)
        errno = ENOMEM;

    return p;
}

void free(void* ptr)
{
    return oe_free(ptr);
}

void* calloc(size_t nmemb, size_t size)
{
    void* p = oe_calloc(nmemb, size);

    if (!p && nmemb && size)
        errno = ENOMEM;

    return p;
}

void* realloc(void* ptr, size_t size)
{
    void* p = oe_realloc(ptr, size);

    if (!p && size)
        errno = ENOMEM;

    return p;
}

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_posix_memalign(memptr, alignment, size);
}

void* memalign(size_t alignment, size_t size)
{
    void* p = oe_memalign(alignment, size);

    if (!p && size)
        errno = ENOMEM;

    return p;
}
