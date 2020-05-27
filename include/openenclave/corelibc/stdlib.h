// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* DISCLAIMER:
 * This header is published with no guarantees of stability and is not part
 * of the Open Enclave public API surface. It is only intended to be used
 * internally by the OE runtime. */

#ifndef _OE_STDLIB_H
#define _OE_STDLIB_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/limits.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

typedef struct _oe_syscall_path
{
    char buf[OE_PATH_MAX];
} oe_syscall_path_t;

extern bool oe_use_debug_malloc;

extern bool oe_use_debug_malloc_memset;

void* oe_malloc(size_t size);

void oe_free(void* ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

void oe_memalign_free(void* ptr);

void* oe_memalign(size_t alignment, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

size_t oe_malloc_usable_size(void* ptr);

unsigned long int oe_strtoul(const char* nptr, char** endptr, int base);

int oe_atexit(void (*function)(void));

char* oe_realpath(const char* path, oe_syscall_path_t* resolved_path);

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

OE_INLINE char* realpath(const char* path, char* resolved_path)
{
    return oe_realpath(path, (oe_syscall_path_t*)resolved_path);
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
