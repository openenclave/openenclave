// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STDLIB_H
#define _ENCLAVELIBC_STDLIB_H

#include "bits/common.h"

ENCLAVELIBC_INLINE
void* malloc(size_t size)
{
    return __enclavelibc.malloc(size);
}

ENCLAVELIBC_INLINE
void free(void* ptr)
{
    return __enclavelibc.free(ptr);
}

ENCLAVELIBC_INLINE
void* calloc(size_t nmemb, size_t size)
{
    return __enclavelibc.calloc(nmemb, size);
}

ENCLAVELIBC_INLINE
void* realloc(void* ptr, size_t size)
{
    return __enclavelibc.realloc(ptr, size);
}

#endif /* _ENCLAVELIBC_STDLIB_H */
