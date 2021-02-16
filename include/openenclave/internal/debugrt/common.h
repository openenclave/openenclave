// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file common.h
 *
 * This file defines the structures and functions used by both
 * host-side and enclave-side debugger runtimes.
 */
#ifndef _OE_DEBUGRT_COMMON_H
#define _OE_DEBUGRT_COMMON_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/defs.h> // For OE_STATIC_ASSERT

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

#define OE_DEBUG_MODULE_VERSION 1
#define OE_DEBUG_MODULE_MAGIC 0xf67ae6230a18a2ce

OE_EXTERNC_BEGIN

typedef struct _debug_module_t
{
    // Magic value and version.
    uint64_t magic;
    uint64_t version;

    // The next module in the list of modules of an enclave.
    struct _debug_module_t* next;

    // Path to the module binary file (ELF) and length of the path.
    // UTF-8 encoding.
    const char* path;
    uint64_t path_length;

    // The address at which the module has been loaded.
    const void* base_address;
    uint64_t size;

    // The enclave to which this module belongs.
    struct _debug_enclave_t* enclave;
} oe_debug_module_t;

OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, magic) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, version) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, next) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, path) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, path_length) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, base_address) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, enclave) == 56);

////////////////////////////////////////////////////////////////////////////////
////////  Functions called by OE SDK host/enclave runtimes  ////////////////////
////////////////////////////////////////////////////////////////////////////////

/**
 * Notify debugrt that a module has been loaded.
 * This function will add the module to the enclave's list of modules and
 * then invoke the oe_debug_notify_module_loaded_hook function.
 * The module structure must be alive until the enclave has been terminated.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_module_loaded(oe_debug_module_t* module);

/**
 * Notify debugrt that a module has been unloaded.
 * This function will remove the module from the enclave's list of modules and
 * then invoke the oe_debug_notify_module_unloaded_hook function.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_module_unloaded(oe_debug_module_t* module);

////////////////////////////////////////////////////////////////////////////////
////////  Hook functions for debuggers to insert breakpoints.  /////////////////
////////////////////////////////////////////////////////////////////////////////

/**
 * The debugger is expected to set a breakpoint in the hook function and read
 * the module structure via the register used for first parameter according to
 * the current ABI. The debugger must ignore duplicate notification for a
 * module. This can happen if the debugger is attached after the module has been
 * added to the list of modules, but before the hook function is called.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_module_loaded_hook(oe_debug_module_t* module);

/**
 * The debugger is expected to set a breakpoint in the hook function and read
 * the module structure via the register used for first parameter according to
 * the current ABI. The debugger must ignore any notification for a module that
 * it has no record of. This can happen if the debugger is attached after the
 * module has been removed from the list, but before the hook is called.
 */
OE_DEBUGRT_EXPORT oe_result_t
oe_debug_notify_module_unloaded_hook(oe_debug_module_t* module);

OE_EXTERNC_END

#endif // _OE_DEBUGRT_COMMON_H
