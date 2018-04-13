// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_ENCLAVE_H
#define _OE_HOST_ENCLAVE_H

#include <openenclave/bits/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/properties.h>
#include <stdbool.h>
#include "asmdefs.h"
#include "hostthread.h"

#if defined(_WIN32)
#include <windows.h>
#endif

typedef struct _EnclaveEvent
{
#if defined(__linux__)
    uint32_t value;
#elif defined(_WIN32)
    HANDLE handle;
#endif
} EnclaveEvent;

#define ENCLAVE_MAGIC 0x20dc98463a5ad8b8

typedef struct _ECallNameAddr
{
    /* ECALL function name */
    char* name;

    /* Code of the name field, calculated by StrCode() */
    uint64_t code;

    /* Virtual address of ECALL function */
    uint64_t vaddr;
} ECallNameAddr;

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

typedef struct _ThreadBinding
{
    /* Address of the enclave's thread control structure */
    uint64_t tcs;

    /* The thread this slot is assigned to */
    OE_H_Thread thread;

    /* Flags */
    uint64_t flags;

    /* The number of bindings in effect */
    uint64_t count;

    /* Event signaling object for enclave threading implementation */
    EnclaveEvent event;
} ThreadBinding;

OE_STATIC_ASSERT(OE_OFFSETOF(ThreadBinding, tcs) == ThreadBinding_tcs);

/* Whether this binding is busy */
#define _OE_THREAD_BUSY 0X1UL

/* Whether the thread is handling an exception */
#define _OE_THREAD_HANDLING_EXCEPTION 0X2UL

/* Get thread data from thread-specific data (TSD) */
ThreadBinding* GetThreadBinding(void);

/* Max number of threads in an enclave supported */
#define OE_SGX_MAX_TCS 32

struct _OE_Enclave
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
    OE_H_Mutex lock;

    /* Hash of enclave (MRENCLAVE) */
    OE_SHA256 hash;

    /* Array of ECALL entry points */
    ECallNameAddr* ecalls;
    size_t num_ecalls;

    /* Debug mode */
    bool debug;

    /* Simulation mode */
    bool simulate;
};

/* Get the event for the given TCS */
EnclaveEvent* GetEnclaveEvent(OE_Enclave* enclave, uint64_t tcs);

/* Initialize the exception processing. */
void _OE_InitializeHostException(void);

#endif /* _OE_HOST_ENCLAVE_H */
