// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_STDLIB_H
#define _OE_HOST_STDLIB_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <stdlib.h>
#include <string.h>

OE_EXTERNC_BEGIN

OE_INLINE
void* oe_malloc(size_t size)
{
    return malloc(size);
}

OE_INLINE
void oe_free(void* ptr)
{
    free(ptr);
}

OE_INLINE
void* oe_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

OE_INLINE
void* oe_realloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

/* oe_memalign has an implementation on the host side.
 * TODO: oehost implements this to split between Win32 & Linux impls,
 * but expects that oe_memalign is paired with oe_memalign_free for Win32.
 * This will be a problem for common code shared between host & enclave,
 * though as of v0.41, nothing in common uses oe_memalign.
 */

OE_INLINE
int oe_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return posix_memalign(memptr, alignment, size);
}

OE_INLINE
unsigned long int oe_strtoul(const char* nptr, char** endptr, int base)
{
    return strtoul(nptr, endptr, base);
}

OE_INLINE
int oe_atexit(void (*function)(void))
{
    return atexit(function);
}

OE_EXTERNC_END

#endif /* _OE_HOST_STDLIB_H */
