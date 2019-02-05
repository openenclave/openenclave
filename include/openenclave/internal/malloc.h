// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_MALLOC_H
#define _OE_MALLOC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef void (*oe_allocation_failure_callback_t)(
    const char* file,
    size_t line,
    const char* func,
    size_t size);

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function);

typedef struct _oe_malloc_stats
{
    uint64_t peak_system_bytes;
    uint64_t system_bytes;
    uint64_t in_use_bytes;
} oe_malloc_stats_t;

/**
 * Obtains enclave malloc statistics.
 *
 * This function obtains malloc statistics for the calling enclave. The enclave
 * must link the **oelibc** library, where this function is defined. These
 * statistics include:
 *
 *     - the peak system bytes allocated
 *     - the current system bytes allocated
 *     - the number of bytes in use
 *
 * @param stats[output] the malloc statistics
 *
 * @return 0 success
 * @return -1 failure
 */
int oe_get_malloc_stats(oe_malloc_stats_t* stats);

/* Dump the list of all in-use allocations */
void oe_debug_malloc_dump(void);

/* Print trace of memory still in use. Return number of blocks allocated. */
size_t oe_debug_malloc_check(void);

//
// If true, oe_debug_malloc_check() is not called on enclave termination.
// To use this mechanism in an enclave:
//
//     #include <openenclave/internal/malloc.h>
//     .
//     .
//     .
//     oe_disable_debug_malloc_check = true;
//
// The variable must be set prior to enclave termination so it is best to
// set it as soon as the enclave is entered.
//
extern bool oe_disable_debug_malloc_check;

/*
**==============================================================================
**
** Applications may replace the default allocator by overriding these functions.
**
** Note: the OE thread binding model binds a thread on enclave entry and severs
** the binding on enclave exit. So the startup and teardown routines are called
** on enclave entry and enclave exit.
**
**==============================================================================
*/

void oe_allocator_startup(void);

void oe_allocator_teardown(void);

void* oe_allocator_malloc(size_t size);

void* oe_allocator_calloc(size_t nmemb, size_t size);

void* oe_allocator_realloc(void* ptr, size_t size);

void* oe_allocator_memalign(size_t alignment, size_t size);

int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size);

void oe_allocator_free(void* ptr);

int oe_allocator_get_stats(oe_malloc_stats_t* stats);

OE_EXTERNC_END

#endif /* _OE_MALLOC_H */
