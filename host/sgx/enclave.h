// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_ENCLAVE_H
#define _OE_HOST_ENCLAVE_H

#include <openenclave/bits/properties.h>
#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/sgxcreate.h>
#include <stdbool.h>
#include "../hostthread.h"
#include "asmdefs.h"

#if defined(_WIN32)
#include <windows.h>
#endif

typedef struct _enclave_event
{
#if defined(__linux__)
    uint32_t value;
#elif defined(_WIN32)
    HANDLE handle;
#endif
} EnclaveEvent;

#define ENCLAVE_MAGIC 0x20dc98463a5ad8b8

/*
**==============================================================================
**
** ThreadBinding:
**
**     Defines a binding between a host thread (ThreadBinding.thread) and an
**     enclave thread context (ThreadBinding.tcs). When the host performs an
**     ECALL, the calling thread "binds" to a thread context within the
**     enclave. This binding remains in effect until the ECALL returns.
**
**     An active binding is indicated by the following condition:
**
**         ThreadBinding.busy == true
**
**     Due to nesting, the same thread may bind to the same enclave thread
**     context more than once. The ThreadBinding.count field indicates how
**     many bindings are in effect.
**
**==============================================================================
*/

typedef struct _thread_binding
{
    /* Address of the enclave's thread control structure */
    uint64_t tcs;

    /* The thread this slot is assigned to */
    oe_thread thread;

    /* Flags */
    uint64_t flags;

    /* The number of bindings in effect */
    uint64_t count;

    /* Event signaling object for enclave threading implementation */
    EnclaveEvent event;

    /* The host GS and FS values saved before making an ecall */
    void* host_gs;
    void* host_fs;
} ThreadBinding;

OE_STATIC_ASSERT(OE_OFFSETOF(ThreadBinding, tcs) == ThreadBinding_tcs);

/* Whether this binding is busy */
#define _OE_THREAD_BUSY 0X1UL

/* Whether the thread is handling an exception */
#define _OE_THREAD_HANDLING_EXCEPTION 0X2UL

/* Get thread data from thread-specific data (TSD) */
ThreadBinding* GetThreadBinding(void);

/**
 *  This structure must be kept in sync with the defines in
 *  debugger/pythonExtension/gdb_sgx_plugin.py.
 */
struct _oe_enclave
{
    /* A "magic number" to validate structure */
    uint64_t magic;

    /* Path of the enclave file */
    char* path;

    /* Base address of enclave within enclave address space (BASEADDR) */
    uint64_t addr;

    /* Address of .text section (for gdb) */
    uint64_t text;

    /* Size of enclave in bytes */
    uint64_t size;

    /* Array of thread bindings */
    ThreadBinding bindings[OE_SGX_MAX_TCS];
    size_t num_bindings;
    oe_mutex lock;

    /* Hash of enclave (MRENCLAVE) */
    OE_SHA256 hash;

    /* Array of ocall functions */
    const oe_ocall_func_t* ocalls;
    size_t num_ocalls;

    /* Debug mode */
    bool debug;

    /* Simulation mode */
    bool simulate;

    /* Meta-data needed by debugrt  */
    oe_debug_enclave_t* debug_enclave;
};

// Static asserts for consistency with
// debugger/pythonExtension/gdb_sgx_plugin.py
#if defined(__linux__)
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_t, magic) == 0);

// Python plugin only needs the field number which is 2
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_t, addr) == 2 * sizeof(void*));

// The fields up to binding correspond to 'ENCLAVE_HEADER'
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_t, bindings) == 0x28);

OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_t, debug) == 0x788);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_enclave_t, debug) + 1 ==
    OE_OFFSETOF(oe_enclave_t, simulate));
#endif

/* Get the event for the given TCS */
EnclaveEvent* GetEnclaveEvent(oe_enclave_t* enclave, uint64_t tcs);

#endif /* _OE_HOST_ENCLAVE_H */
