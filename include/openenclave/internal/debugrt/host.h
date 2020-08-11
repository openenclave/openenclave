// Copyright (c) Open Enclave SDK contributors.
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

/**
 * If debugrt is built as a shared library, then symbols are exported.
 * Otherwise, symbols are not exported.
 *
 * In Linux, debugrt is built as a static library that the host application
 * links against. The debugrt is subsumed by the host application.
 *
 * In Windows, debugrt is built as a shared library. The host application
 * dynamically loads oedebugrt.dll and calls functions via a bridge.
 * This allows applications to be executed even when oedeburt.dll is not found
 * on the system. Additionally, release enclaves are completely decoupled from
 * oedeburt.dll. See host/sgx/windows/debugrtbridge.c
 */

#ifdef OE_BUILDING_DEBUGRT_SHARED_LIBRARY
#define OE_DEBUGRT_EXPORT OE_EXPORT
#else
#define OE_DEBUGRT_EXPORT
#endif

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

#define OE_DEBUG_THREAD_BINDING_MAGIC 0x24cb0317d077d636

typedef struct _debug_thread_binding_t
{
    uint64_t magic;
    uint64_t version;
    struct _debug_thread_binding_t* next;

    uint64_t thread_id;
    oe_debug_enclave_t* enclave;
    struct _sgx_tcs* tcs;
} oe_debug_thread_binding_t;

OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_thread_binding_t, magic) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_thread_binding_t, version) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_thread_binding_t, next) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_thread_binding_t, thread_id) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_thread_binding_t, enclave) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_thread_binding_t, tcs) == 40);

typedef struct _debug_module_t
{
    uint64_t magic;
    uint64_t version;
    char* path;
    uint64_t path_length;
    uint64_t base_address;
    uint64_t size;
} oe_debug_module_t;

OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, magic) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, version) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, path) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, path_length) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, base_address) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, size) == 40);

#define OE_DEBUG_MODULE_MAGIC 0x0ccad3302d644b28

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
OE_DEBUGRT_EXPORT extern uint32_t oe_debugger_contract_version;

/**
 * The list of loaded enclaves.
 * Upon attaching to an application, the debugger can scan this list
 * and configure the enclaves for debugging.
 */
OE_DEBUGRT_EXPORT extern oe_debug_enclave_t* oe_debug_enclaves_list;

/**
 * The list of active thread bindings.
 * The debugger can scan this list to find the list of bindings.
 * Note: Ideally, this list could be stored per thread in thread-local storage.
 */
OE_DEBUGRT_EXPORT extern oe_debug_thread_binding_t*
    oe_debug_thread_bindings_list;

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
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_enclave_created(oe_debug_enclave_t* enclave);

/**
 * Notify debugrt that and enclave has been terminated.
 * This notification must be done after calling enclave destructors.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_enclave_terminated(oe_debug_enclave_t* enclave);

/**
 * Notify debugrt about a new binding for current thread.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_push_thread_binding(oe_debug_enclave_t* enclave, struct _sgx_tcs* tcs);

/**
 * Pop the last binding for the current thread.
 */
OE_DEBUGRT_EXPORT oe_result_t oe_debug_pop_thread_binding(void);

/**
 * Notify that a module has been loaded within enclave address space.
 */
OE_DEBUGRT_EXPORT
oe_result_t oe_debug_notify_module_loaded(oe_debug_module_t* module);

/**
 * Notify that a module is about to be unloaded within enclave address space.
 */
OE_DEBUGRT_EXPORT
oe_result_t oe_debug_notify_module_unloaded(oe_debug_module_t* module);

OE_EXTERNC_END

#endif // _OE_DEBUGRT_HOST_H
