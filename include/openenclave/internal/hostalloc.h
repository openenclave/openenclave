// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOSTALLOC_H
#define _OE_HOSTALLOC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Allocates space from host memory. This function is intended to obtain
 * memory for oe_call_host arguments. For repeated small allocations,
 * performance of oe_host_alloc_for_call_host() will generally be higher than
 * oe_host_malloc().
 *
 * Note: Memory allocated by oe_host_alloc_for_call_host() must be freed by
 * oe_host_free_for_call_host(), in reverse order of allocation.
 *
 * @param size The number of bytes to allocate.
 *
 * @returns Returns the address of the allocated space, or NULL in case of
 *          error.
 */
void* oe_host_alloc_for_call_host(size_t size);

/**
 * Frees space allocated w/ oe_host_alloc_for_call_host().
 *
 * Note: Memory allocated by oe_host_alloc_for_call_host() must be freed by
 * oe_host_free_for_call_host(), in reverse order of allocation.
 *
 * @param p Address returned by previous call to oe_host_alloc_for_call_host().
 *      Can be NULL.
 */
void oe_host_free_for_call_host(void* p);

OE_EXTERNC_END

#endif /* _OE_HOSTALLOC_H */
