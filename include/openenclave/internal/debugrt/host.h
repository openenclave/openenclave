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
#include <openenclave/internal/defs.h> // For OE_STATIC_ASSERT
#include <stdint.h>
#include <wchar.h>

OE_EXTERNC_BEGIN

#define OE_DEBUG_ENCLAVE_VERSION 1

#define OE_DEBUG_ENCLAVE_MAGIC 0xabc540ee14fa48ce

#define OE_DEBUG_ENCLAVE_MASK_DEBUG 0x01
#define OE_DEBUG_ENCLAVE_MASK_SIMULATE 0x02

typedef struct _debug_enclave_t
{
    uint64_t magic;

    uint64_t version;

    struct _debug_enclave_t* next;

    const char* path;
    uint64_t path_length;

    const void* base_address;
    uint64_t size;

    struct _sgx_tcs** tcs_array;
    uint64_t num_tcs;

    uint64_t flags;
} oe_debug_enclave_t;

OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, magic) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, version) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, next) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, path) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, path_length) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, base_address) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, tcs_array) == 56);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, num_tcs) == 64);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_enclave_t, flags) == 72);

////////////////////////////////////////////////////////////////////////////////
/////////////// Symbols Exported by the Runtime ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/**
 * The current version of the debugger contract supported by the application
 * (debugrt).
 *
 * The debugger is expected to check the value of this variable to determine
 * if it can debug the application or not. If it cannot debug the application,
 * the debugger is expected to advise the user to use a newer version of the
 * that understands the specific version of the contract.
 */
OE_EXPORT extern uint32_t oe_debugger_contract_version;

/**
 * The list of loaded enclaves.
 * Upon attaching to an application, the debugger can scan this list
 * and configure the enclaves for debugging.
 */
OE_EXPORT extern oe_debug_enclave_t* oe_debug_enclaves_list;

////////////////////////////////////////////////////////////////////////////////
/////////////// Events Raised for Windows Debuggers/////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#if defined(_WIN32)

/**
 * The following event is raised by the runtime when an enclave is created:
 *   ULONG_PTR args[1] = { oe_debug_enclave_t_ptr };
 *   RaiseException(OE_DEBUGRT_ENCLAVE_CREATED_EVENT,
 *                  0,  // dwExceptionFlags
 *                  1,  // always 1 (number of argument)
 *                  args)
 * The oe_debug_enclave_t structure corresponding to the created enclave is
 * passed as the sole element of the argument array.
 */
#define OE_DEBUGRT_ENCLAVE_CREATED_EVENT 0x0edeb646

/**
 * The following event is raised by the runtime after an enclave has been
 * terminated:
 *   ULONG_PTR args[1] = { oe_debug_enclave_t_ptr };
 *   RaiseException(OE_DEBUGRT_ENCLAVE_TERMINATED_EVENT,
 *                  0,  // dwExceptionFlags
 *                  1,  // always 1 (number of argument)
 *                  args)
 * The oe_debug_enclave_t structure corresponding to the created enclave is
 * passed as the sole element of the argument array.
 */
#define OE_DEBUGRT_ENCLAVE_TERMINATED_EVENT 0x0edeb647

#endif

////////////////////////////////////////////////////////////////////////////////
/////////////// Functions called by OE SDK  ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/**
 * Notify debugrt that an enclave has been created.
 * This notification must be done before initializing the enclave.
 */
OE_EXPORT oe_result_t
oe_debug_notify_enclave_created(oe_debug_enclave_t* enclave);

/**
 * Notify debugrt that and enclave has been terminated.
 * This notification must be done after calling enclave destructors.
 */
OE_EXPORT oe_result_t
oe_debug_notify_enclave_terminated(oe_debug_enclave_t* enclave);

OE_EXTERNC_END

#endif // _OE_DEBUGRT_HOST_H
