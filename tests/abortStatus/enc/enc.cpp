// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <atomic>
#include "abortStatus_t.h"

// Explicitly call oe_abort to abort the enclave.
int regular_abort(void)
{
    oe_abort();

    oe_host_printf("Error: unreachable code is reached.\n");
    return -1;
}

// When an un-handled hardware exception happens, enclave should abort itself.
int generate_unhandled_hardware_exception(void)
{
    // Generate a hardware exception via an undefined instruction. Since there
    // is no handler to handle it, the enclave should abort itself.
    asm volatile("ud2" ::: "memory");
    // We should never get here...
    oe_host_printf("Error: unreachable code is reached. ");
    return -1;
}

int test_ocall_after_abort(void* thread_ready_count, void* is_enclave_crashed)
{
    int rval = -1;

    // Notify control thread that this thread is ready.
    ++(*reinterpret_cast<std::atomic<uint32_t>*>(thread_ready_count));

    // Wait for the is_enclave_crashed signal.
    while (!*reinterpret_cast<std::atomic<bool>*>(is_enclave_crashed))
    {
        continue;
    }

    if (foobar() == OE_ENCLAVE_ABORTING)
    {
        rval = 0;
    }

    return rval;
}

int normal_ecall(void)
{
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages */
    64,   /* NumStackPages */
    5);   /* NumTCS */
