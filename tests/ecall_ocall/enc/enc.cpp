// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h> // for __oe_get_enclave_base()
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <mutex>
#include <system_error>
#include "../args.h"
#include "helpers.h"

unsigned EnclaveId = ~0u;

static TLSWrapper PerThreadFlowId;

// class to verify OCalls in static Initializers
struct StaticInitOcaller
{
    StaticInitOcaller() : m_result(OE_FAILURE)
    {
        m_result =
            oe_call_host("InitOcallHandler", (void*)__oe_get_enclave_base());
        OE_TEST(m_result == OE_OK);
    }
    oe_result_t GetOcallResult() const
    {
        return m_result;
    }

  private:
    oe_result_t m_result;
} StaticInitOcaller_;

// obtain static init ocall result
OE_ECALL void EncGetInitOcallResult(void* Args_)
{
    if (!oe_is_outside_enclave(Args_, sizeof(oe_result_t)))
        return;

    oe_result_t* result = (oe_result_t*)Args_;
    *result = StaticInitOcaller_.GetOcallResult();
}

// Set custom enclave ID for later tracking
OE_ECALL void EncSetEnclaveId(void* Args_)
{
    if (!oe_is_outside_enclave(Args_, sizeof(EncSetEnclaveIdArg)))
        return;

    EncSetEnclaveIdArg* args_host = (EncSetEnclaveIdArg*)Args_;
    EncSetEnclaveIdArg args = *args_host;

    if (EnclaveId != ~0u)
    {
        args_host->result = OE_INVALID_PARAMETER;
    }
    EnclaveId = args.id;
    args_host->base_addr = __oe_get_enclave_base();
    args_host->result = OE_OK;
}

// Parallel execution test. Using a (trivialized) barrier in the host,
// spin-wait until all expected threads reach it, w/o performing an ocall.
OE_ECALL void EncParallelExecution(void* Args_)
{
    if (!oe_is_outside_enclave(Args_, sizeof(EncParallelExecutionArg)))
        return;

    EncParallelExecutionArg* args_host = (EncParallelExecutionArg*)Args_;
    EncParallelExecutionArg args = *args_host;

    if (!oe_is_outside_enclave((void*)args.counter, sizeof(unsigned)) ||
        !oe_is_outside_enclave((void*)args.release, sizeof(unsigned)))
        return;

    unsigned old_flow_id = PerThreadFlowId.GetU();
    if (old_flow_id)
    {
        printf(
            "%s(): Starting flow=%u, though thread already has %u\n",
            __FUNCTION__,
            args.flow_id,
            old_flow_id);
        return;
    }
    PerThreadFlowId.Set(args.flow_id);

    __atomic_add_fetch(args.counter, 1, __ATOMIC_SEQ_CST);
    while (!*args.release)
        ;

    old_flow_id = PerThreadFlowId.GetU();
    if (old_flow_id != args.flow_id)
    {
        printf(
            "%s(): Stopping flow=%u, though overwritten with %u\n",
            __FUNCTION__,
            args.flow_id,
            old_flow_id);
        return;
    }
    PerThreadFlowId.Set(0u);

    args_host->result = OE_OK;
}

// Exported helper function for reachability test
OE_ECALL void EncDummyEncFunction(void*)
{
}

// Non-exported helper function for reachability test
extern "C" void EncUnExportedFunction(void*)
{
}

// Reachability test calling the host
OE_ECALL void EncTestCallHostFunction(void* Args_)
{
    if (!oe_is_outside_enclave(Args_, sizeof(EncTestCallHostFunctionArg)))
        return;

    EncTestCallHostFunctionArg* args_host = (EncTestCallHostFunctionArg*)Args_;
    EncTestCallHostFunctionArg args = *args_host;

    // Testing for a string to be outside the enclave is ugly. We might want
    // to provide a helper.
    if (!oe_is_outside_enclave(args.function_name, 1))
    {
        args_host->result = OE_INVALID_PARAMETER;
        return;
    }

    args_host->result = oe_call_host(args.function_name, NULL);
}

size_t Factor = 0;

OE_ECALL void EncCrossEnclaveCall(CrossEnclaveCallArg* arg)
{
    uint32_t my_input = arg->input;
    uint32_t my_enclave_id = arg->enclave_id;

    // Call next enclave via host.
    ++arg->input;
    ++arg->enclave_id;
    OE_TEST(oe_call_host("CrossEnclaveCall", arg) == OE_OK);

    // augment result with my result.
    uint32_t my_result = static_cast<uint32_t>(my_input * Factor);
    arg->output += my_result;
    printf(
        "enclave %u: Factor=%lu, myResult = %u, arg.output=%u\n",
        my_enclave_id,
        Factor,
        my_result,
        arg->output);
}

OE_ECALL void EncSetFactor(void* arg)
{
    Factor = (size_t)arg;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    5);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
