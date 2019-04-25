// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_STDLIB_H
#define _OE_STDLIB_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/defs.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

/* Implementations taken directly from MUSL */
void srand(unsigned s);
int rand(void);

void* oe_malloc(size_t size);

void oe_free(void* ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

void* oe_memalign(size_t alignment, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

unsigned long int oe_strtoul(const char* nptr, char** endptr, int base);

long int oe_strtol(const char* nptr, char** endptr, int base);

int oe_atexit(void (*function)(void));

char* oe_realpath(const char* path, char* resolved_path);

void oe_abort(void);

OE_NO_RETURN void oe_exit(int status);

int oe_atoi(const char* nptr);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#include <openenclave/corelibc/bits/atexit.h>
#include <openenclave/corelibc/bits/malloc.h>
#include <openenclave/corelibc/bits/strtoul.h>

OE_INLINE long int strtol(const char* nptr, char** endptr, int base)
{
    return oe_strtol(nptr, endptr, base);
}

OE_INLINE char* realpath(const char* path, char* resolved_path)
{
    return oe_realpath(path, resolved_path);
}

OE_INLINE void abort(void)
{
    oe_abort();
}

OE_INLINE void exit(int status)
{
    return oe_exit(status);
}

OE_INLINE int atoi(const char* nptr)
{
    return oe_atoi(nptr);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_STDLIB_H */
