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
    uint64_t peakSystemBytes;
    uint64_t systemBytes;
    uint64_t inUseBytes;
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
oe_result_t oe_get_malloc_stats(oe_malloc_stats_t* stats);

void* oe_malloc(size_t size);

void oe_free(void *ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

void* oe_memalign(size_t alignment, size_t size);

OE_EXTERNC_END

#endif /* _OE_MALLOC_H */
