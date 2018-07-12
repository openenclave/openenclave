// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_STDLIB_H
#define _OE_ENCLAVELIBC_STDLIB_H

#include "bits/common.h"

OE_ENCLAVELIBC_EXTERNC_BEGIN

#define OE_RAND_MAX (0x7fffffff)

int oe_rand(void);

void* oe_malloc(size_t size);

void oe_free(void* ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

void* oe_memalign(size_t alignment, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

unsigned long int oe_strtoul(const char* nptr, char** endptr, int base);

int oe_atexit(void (*function)(void));

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

#define RAND_MAX OE_RAND_MAX

OE_ENCLAVELIBC_INLINE
int rand(void)
{
    return oe_rand();
}

OE_ENCLAVELIBC_INLINE
void* malloc(size_t size)
{
    return oe_malloc(size);
}

OE_ENCLAVELIBC_INLINE
void free(void* ptr)
{
    return oe_free(ptr);
}

OE_ENCLAVELIBC_INLINE
void* calloc(size_t nmemb, size_t size)
{
    return oe_calloc(nmemb, size);
}

OE_ENCLAVELIBC_INLINE
void* realloc(void* ptr, size_t size)
{
    return oe_realloc(ptr, size);
}

OE_ENCLAVELIBC_INLINE
void* memalign(size_t alignment, size_t size)
{
    return oe_memalign(alignment, size);
}

OE_ENCLAVELIBC_INLINE
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return oe_posix_memalign(memptr, alignment, size);
}

OE_ENCLAVELIBC_INLINE
unsigned long int strtoul(const char* nptr, char** endptr, int base)
{
    return oe_strtoul(nptr, endptr, base);
}

OE_ENCLAVELIBC_INLINE
int atexit(void (*function)(void))
{
    return oe_atexit(function);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_STDLIB_H */
