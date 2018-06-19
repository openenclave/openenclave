// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_STDLIB_H
#define _ENCLAVELIBC_STDLIB_H

#include "bits/common.h"

#define RAND_MAX (0x7fffffff)

OE_INLINE
int rand(void)
{
    return oe_rand();
}

OE_INLINE
void* malloc(size_t size)
{
    return oe_malloc(size);
}

OE_INLINE
void free(void* ptr)
{
    return oe_free(ptr);
}

OE_INLINE
void* calloc(size_t nmemb, size_t size)
{
    return oe_calloc(nmemb, size);
}

OE_INLINE
void* realloc(void* ptr, size_t size)
{
    return oe_realloc(ptr, size);
}

OE_INLINE
void* memalign(size_t alignment, size_t size)
{
    return oe_memalign(alignment, size);
}

OE_INLINE
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_posix_memalign(memptr, alignment, size);
}

OE_INLINE
unsigned long int strtoul(const char* nptr, char** endptr, int base)
{
    return oe_strtoul(nptr, endptr, base);
}

#endif /* _ENCLAVELIBC_STDLIB_H */
