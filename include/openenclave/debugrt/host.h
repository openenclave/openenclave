// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file host.h
 *
 * This file defines the structures and functions used by the
 * host-side debugger runtime.
 */
#ifndef _OE_DEBUGRT_HOST_H
#define _OE_DEBUGRT_HOST_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h> // For OE_STATIC_ASSERT

OE_EXTERNC_BEGIN

#ifdef __linux__
typedef int32_t wide_char_t;
#else
typedef int16_t wide_char_t;
#endif

#define OE_DEBUG_ENCLAVE_MAGIC 0xabc540ee14fa48ce

typedef struct _debug_enclave_t
{
    uint64_t magic;

    const char* path;
    const wide_char_t* wpath;

    const void* base_address;

    struct _sgx_tcs** tcs;
    uint64_t num_tcs;

    bool debug;
    bool simulate;

    struct _debug_enclave_t* next;
} oe_debug_enclave_t;

OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, magic) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, path) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, wpath) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, base_address) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, tcs) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, num_tcs) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, debug) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, simulate) == 49);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, next) == 56);

OE_EXPORT extern oe_debug_enclave_t* oe_debug_enclaves_list;

OE_EXPORT oe_result_t
oe_debug_notify_enclave_created(oe_debug_enclave_t* enclave);
OE_EXPORT oe_result_t
oe_debug_notify_enclave_terminated(oe_debug_enclave_t* enclave);

OE_EXTERNC_END

#endif // _OE_DEBUGRT_HOST_H
