// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_STDLIB_H
#define _ELIBC_STDLIB_H

#include "bits/common.h"

ELIBC_EXTERNC_BEGIN

#define ELIBC_RAND_MAX (0x7fffffff)

int elibc_rand(void);

void* elibc_malloc(size_t size);

void elibc_free(void* ptr);

void* elibc_calloc(size_t nmemb, size_t size);

void* elibc_realloc(void* ptr, size_t size);

void* elibc_memalign(size_t alignment, size_t size);

int elibc_posix_memalign(void** memptr, size_t alignment, size_t size);

unsigned long int elibc_strtoul(const char* nptr, char** endptr, int base);

int elibc_atexit(void (*function)(void));

#if defined(ELIBC_NEED_STDC_NAMES)

#define RAND_MAX ELIBC_RAND_MAX

ELIBC_INLINE
int rand(void)
{
    return elibc_rand();
}

ELIBC_INLINE
void* malloc(size_t size)
{
    return elibc_malloc(size);
}

ELIBC_INLINE
void free(void* ptr)
{
    elibc_free(ptr);
}

ELIBC_INLINE
void* calloc(size_t nmemb, size_t size)
{
    return elibc_calloc(nmemb, size);
}

ELIBC_INLINE
void* realloc(void* ptr, size_t size)
{
    return elibc_realloc(ptr, size);
}

ELIBC_INLINE
void* memalign(size_t alignment, size_t size)
{
    return elibc_memalign(alignment, size);
}

ELIBC_INLINE
int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return elibc_posix_memalign(memptr, alignment, size);
}

ELIBC_INLINE
unsigned long int strtoul(const char* nptr, char** endptr, int base)
{
    return elibc_strtoul(nptr, endptr, base);
}

ELIBC_INLINE
int atexit(void (*function)(void))
{
    return elibc_atexit(function);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_STDLIB_H */
