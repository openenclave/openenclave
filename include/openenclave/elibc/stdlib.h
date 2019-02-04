// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_STDLIB_H
#define _OE_STDLIB_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Implementations taken directly from MUSL */
void srand(unsigned s);
int rand(void);

void* oe_malloc(size_t size);

void oe_free(void* ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

void* oe_memalign(size_t alignment, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

unsigned long int elibc_strtoul(const char* nptr, char** endptr, int base);

int oe_atexit(void (*function)(void));

#if defined(OE_NEED_STDC_NAMES)

#include "bits/atexit.h"
#include "bits/malloc.h"

OE_INLINE
unsigned long int strtoul(const char* nptr, char** endptr, int base)
{
    return elibc_strtoul(nptr, endptr, base);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_STDLIB_H */
