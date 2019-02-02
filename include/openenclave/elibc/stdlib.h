// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_STDLIB_H
#define _OE_STDLIB_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_RAND_MAX (0x7fffffff)

int elibc_rand(void);

void* oe_malloc(size_t size);

void oe_free(void* ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

void* oe_memalign(size_t alignment, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

unsigned long int elibc_strtoul(const char* nptr, char** endptr, int base);

int elibc_atexit(void (*function)(void));

#if defined(OE_NEED_STDC_NAMES)

#include "bits/malloc.h"

#define RAND_MAX OE_RAND_MAX

OE_INLINE
int rand(void)
{
    return elibc_rand();
}

OE_INLINE
unsigned long int strtoul(const char* nptr, char** endptr, int base)
{
    return elibc_strtoul(nptr, endptr, base);
}

OE_INLINE
int atexit(void (*function)(void))
{
    return elibc_atexit(function);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_STDLIB_H */
