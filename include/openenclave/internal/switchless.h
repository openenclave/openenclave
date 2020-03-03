// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SWITCHLESS_H
#define _OE_SWITCHLESS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>

typedef struct _host_worker_context
{
    volatile oe_call_host_function_args_t* call_arg;
    oe_enclave_t* enclave;
    volatile bool is_stopping;

    volatile int32_t event;

    // Number of times the worker spun without seeing a message.
    uint64_t spin_count;

    // Statistics.
    uint64_t total_spin_count;
} oe_host_worker_context_t;

/**
 * oe_host_worker_context_t is used both by the host (windows/linux) and the
 * enclave (ELF). Lock down the layout.
 */
OE_STATIC_ASSERT(sizeof(oe_host_worker_context_t) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_host_worker_context_t, call_arg) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_host_worker_context_t, enclave) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_host_worker_context_t, is_stopping) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_host_worker_context_t, event) == 20);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_host_worker_context_t, spin_count) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_host_worker_context_t, total_spin_count) == 32);

typedef struct _enclave_worker_context
{
    volatile oe_call_enclave_function_args_t* call_arg;
    oe_enclave_t* enclave;
    volatile bool is_stopping;

    volatile int32_t event;

    // Number of times the worker spun without seeing a message.
    uint64_t spin_count;

    // The limit at which to stop spinning and return to host to sleep.
    uint64_t spin_count_threshold;

    // Statistics.
    uint64_t total_spin_count;
} oe_enclave_worker_context_t;

/**
 * oe_enclave_worker_context_t is used both by the host (windows/linux) and the
 * enclave (ELF). Lock down the layout.
 */
OE_STATIC_ASSERT(sizeof(oe_enclave_worker_context_t) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_worker_context_t, call_arg) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_worker_context_t, enclave) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_worker_context_t, is_stopping) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_worker_context_t, event) == 20);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_worker_context_t, spin_count) == 24);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_enclave_worker_context_t, spin_count_threshold) == 32);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_enclave_worker_context_t, total_spin_count) == 40);

typedef struct _oe_switchless_call_manager
{
    oe_host_worker_context_t* host_worker_contexts;
    oe_thread_t* host_worker_threads;
    size_t num_host_workers;

    oe_enclave_worker_context_t* enclave_worker_contexts;
    oe_thread_t* enclave_worker_threads;
    size_t num_enclave_workers;
} oe_switchless_call_manager_t;

oe_result_t oe_start_switchless_manager(
    oe_enclave_t* enclave,
    size_t num_host_workers,
    size_t num_enclave_workers);

oe_result_t oe_stop_switchless_manager(oe_enclave_t* enclave);

void oe_host_worker_wait(oe_host_worker_context_t* context);

void oe_host_worker_wake(oe_host_worker_context_t* context);

void oe_enclave_worker_wait(oe_enclave_worker_context_t* context);

void oe_enclave_worker_wake(oe_enclave_worker_context_t* context);

#endif /* _OE_SWITCHLESS_H */
