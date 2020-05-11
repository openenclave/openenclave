// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ECALL_OPTOUT_H
#define _OE_ECALL_OPTOUT_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

#ifdef OE_SWITCHLESS_OPT_OUT
oe_result_t oe_sgx_init_context_switchless_ecall(
    void* host_worker_contexts,
    uint64_t num_host_workers)
{
    OE_UNUSED(host_worker_contexts);
    OE_UNUSED(num_host_workers);
    return OE_UNSUPPORTED;
}

void oe_sgx_switchless_enclave_worker_thread_ecall(void* context)
{
    OE_UNUSED(context);
    return;
}

#endif

OE_EXTERNC_END

#endif // _OE_ECALL_OPTOUT_H
