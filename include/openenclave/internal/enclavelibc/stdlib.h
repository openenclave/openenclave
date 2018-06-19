// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STDLIB_H
#define _ENCLAVELIBC_STDLIB_H

#include "bits/common.h"

OE_INLINE 
int rand(void)
{
    return __enclavelibc.rand();
}

OE_INLINE
void* malloc(size_t size)
{
    return __enclavelibc.malloc(size);
}

OE_INLINE
void free(void* ptr)
{
    return __enclavelibc.free(ptr);
}

OE_INLINE
void* calloc(size_t nmemb, size_t size)
{
    return __enclavelibc.calloc(nmemb, size);
}

OE_INLINE
void* realloc(void* ptr, size_t size)
{
    return __enclavelibc.realloc(ptr, size);
}

OE_INLINE
void* memalign(size_t alignment, size_t size)
{
    return __enclavelibc.memalign(alignment, size);
}

OE_INLINE
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return __enclavelibc.posix_memalign(memptr, alignment, size);
}

#endif /* _ENCLAVELIBC_STDLIB_H */
