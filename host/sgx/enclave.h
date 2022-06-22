// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_ENCLAVE_H
#define _OE_HOST_ENCLAVE_H

#include <openenclave/bits/properties.h>
#include <openenclave/edger8r/host.h>
#include <openenclave/host.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/switchless.h>
#include <stdbool.h>
#include "../ecall_ids.h"
#include "../hostthread.h"
#include "asmdefs.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#define OE_VZEROUPPER              \
    asm volatile("vzeroupper \n\t" \
                 :                 \
                 :                 \
                 : "ymm0",         \
                   "ymm1",         \
                   "ymm2",         \
                   "ymm3",         \
                   "ymm4",         \
                   "ymm5",         \
                   "ymm6",         \
                   "ymm7",         \
                   "ymm8",         \
                   "ymm9",         \
                   "ymm10",        \
                   "ymm11",        \
                   "ymm12",        \
                   "ymm13",        \
                   "ymm14",        \
                   "ymm15")

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
    oe_thread_t thread;

    /* Flags */
    uint64_t flags;

    /* The number of bindings in effect */
    uint64_t count;

    /* Event signaling object for enclave threading implementation */
    EnclaveEvent event;

    /* This field allows the simulation mode exception handler to read enclave
     * properties of the current thread binding */
    struct _oe_enclave* enclave;

    /* Buffer used for ocall parameters */
    void* ocall_buffer;
    uint64_t ocall_buffer_size;
} oe_thread_binding_t;

/* Whether this binding is busy */
#define _OE_THREAD_BUSY 0X1UL

/* Whether the thread is handling an exception */
#define _OE_THREAD_HANDLING_EXCEPTION 0X2UL

/* Get thread data from thread-specific data (TSD) */
oe_thread_binding_t* oe_get_thread_binding(void);

/**
 * Host-side representation of properties associated with each
 * enclave instance.
 */
typedef struct _oe_enclave
{
    /* A "magic number" to validate structure */
    uint64_t magic;

    /* Path of the enclave file */
    char* path;

    /* Base address of enclave address range (BASEADDR). If not,
     * a 0-based enclave, currently base_address = start_address */
    uint64_t base_address;

    /* Enclave image start address within enclave address space */
    uint64_t start_address;

    /* Size of enclave in bytes */
    uint64_t size;

    /* Array of thread bindings */
    oe_thread_binding_t bindings[OE_SGX_MAX_TCS];
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
    oe_debug_module_t* debug_modules;

    /* Manager for switchless calls */
    oe_switchless_call_manager_t* switchless_manager;

    /* Table of global to local ecall ids */
    oe_ecall_id_t* ecall_id_table;
    size_t ecall_id_table_size;
    size_t num_ecalls;
} oe_enclave_t;

/* Get the event for the given TCS */
EnclaveEvent* GetEnclaveEvent(oe_enclave_t* enclave, uint64_t tcs);

/**
 * Size of ocall buffers passed in ecall_contexts. Large enough for most ocalls.
 * If an ocall requires more than this size, then the enclave will make an
 * ocall to allocate the buffer instead of using the ecall_context's buffer.
 * Note: Currently, quotes are about 10KB.
 */
#define OE_DEFAULT_OCALL_BUFFER_SIZE (16 * 1024)

void oe_setup_ecall_context(oe_ecall_context_t* ecall_context);

#endif /* _OE_HOST_ENCLAVE_H */
