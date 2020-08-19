// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "ocalls.h"
#include "platform_u.h"

void oe_sgx_thread_wake_wait_ocall(
    oe_enclave_t* enclave,
    uint64_t waiter_tcs,
    uint64_t self_tcs)
{
    if (!waiter_tcs || !self_tcs)
        return;

    HandleThreadWake(enclave, waiter_tcs);
    HandleThreadWait(enclave, self_tcs);
}
