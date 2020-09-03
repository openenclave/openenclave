// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
/**
 * @file mallinfo.h
 *
 * This file defines an interface that pluggable allocators can implement.
 * See
 * https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/Mallinfo.md
 *
 */

#ifndef OE_ADVANCED_MALLINFO_H
#define OE_ADVANCED_MALLINFO_H

#include <openenclave/bits/result.h>

/**
 * @cond IGNORE
 */
OE_EXTERNC_BEGIN

/**
 * @endcond
 */

typedef struct _oe_mallinfo
{
    /// Maximum number of bytes that can be allocated in total
    size_t max_total_heap_size;
    /// Number of bytes allocated at the moment.
    size_t current_allocated_heap_size;
    /// Highest value reached by `current_allocated_heap_size` during execution.
    size_t peak_allocated_heap_size;
} oe_mallinfo_t;

/**
 * Obtain current memory usage statistics.
 *
 * Users may make this call on allocators that support it, to find out how much
 * memory can be allocated in total, how much is allocated at the moment, and
 * the high watermark of allocation so far.
 *
 * @param[out] info An oe_mallinfo_t struct, to be populated by the allocator.
 *
 * @retval OE_OK Allocation information was set successfully.
 * @retval OE_UNSUPPORTED The allocator does not support this interface.
 * @retval OE_FAILURE Other failure.
 */
oe_result_t oe_allocator_mallinfo(oe_mallinfo_t* info);

OE_EXTERNC_END

#endif // OE_ADVANCED_MALLINFO_H
