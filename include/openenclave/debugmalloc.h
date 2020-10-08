// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file debugmalloc.h
 *
 * This file defines the programming interface for debug malloc.
 *
 */

#ifndef _OE_DEBUGMALLOC_H
#define _OE_DEBUGMALLOC_H

#include <openenclave/bits/result.h>

/**
 * @cond IGNORE
 */
OE_EXTERNC_BEGIN

/**
 * @endcond
 */

/**
 * Function to start the state of local tracking.
 *
 * This function will turn the global variable oe_use_debug_malloc_tracking
 * from false to true. If the previous value is not false, the return value is
 * OE_UNEXPECTED.
 */
oe_result_t oe_debug_malloc_tracking_start(void);

/**
 * Function to stop the state of local tracking.
 *
 * This function will turn the global variable oe_use_debug_malloc_tracking
 * from true to false. If the previous value is not true, the return value is
 * OE_UNEXPECTED.
 */
oe_result_t oe_debug_malloc_tracking_stop(void);

/**
 * Function to show the details about leaks.
 *
 * @param[out] out_object_count the total number of leaks found during the
 * state of local tracking.
 * @param[out] report On success, points to a null-terminated string containing
 * information about these leaks, including the callstack to each leak.  The
 * caller is responsible for freeing the string with oe_free().
 */
oe_result_t oe_debug_malloc_tracking_report(
    uint64_t* out_object_count,
    char** report);

OE_EXTERNC_END

#endif /* _OE_DEBUG_MALLOC_H */
