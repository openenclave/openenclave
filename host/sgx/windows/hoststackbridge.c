// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/context.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/sgxtypes.h>
#include "../asmdefs.h"
#include "../enclave.h"

#pragma code_seg(".oedbgrt")

OE_NEVER_INLINE int
oe_host_stack_bridge(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs,
    oe_enclave_t* enclave,
    oe_ocall_context_t* eexit_frame)
{
    oe_debug_ocall_info_t ocall_info = {0};
    ocall_info.enclave = enclave->debug_enclave;
    ocall_info.tcs = (sgx_tcs_t*) tcs;
    ocall_info.enclave_rip = eexit_frame->ret;
    ocall_info.enclave_rbp = eexit_frame->rbp;
    ocall_info.enclave_rsp = 0;

    oe_debug_notify_ocall_start(&ocall_info);

    int ret = oe_dispatch_ocall(arg1, arg2, arg1_out, arg2_out, tcs, enclave);

    oe_debug_notify_ocall_end();

    return ret;
}
