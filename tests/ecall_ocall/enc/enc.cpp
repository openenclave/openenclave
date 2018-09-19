// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#define OE_TRACE_LEVEL 1

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h> // for __oe_get_enclave_base()
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <mutex>
#include <system_error>
#include "../args.h"
#include "helpers.h"

unsigned EnclaveId = ~0u;

static TLSWrapper PerThreadFlowId;

// class to verify OCalls in static Initializers
struct StaticInitOcaller
{
    StaticInitOcaller() : m_Result(OE_FAILURE)
    {
        m_Result =
            oe_call_host("InitOcallHandler", (void*)__oe_get_enclave_base());
        OE_TEST(m_Result == OE_OK);
    }
    oe_result_t GetOcallResult() const
    {
        return m_Result;
    }

  private:
    oe_result_t m_Result;
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

    EncSetEnclaveIdArg* argsHost = (EncSetEnclaveIdArg*)Args_;
    EncSetEnclaveIdArg args = *argsHost;

    if (EnclaveId != ~0u)
    {
        argsHost->result = OE_INVALID_PARAMETER;
    }
    EnclaveId = args.id;
    argsHost->baseAddr = __oe_get_enclave_base();
    argsHost->result = OE_OK;
}

// Parallel execution test. Using a (trivialized) barrier in the host,
// spin-wait until all expected threads reach it, w/o performing an ocall.
OE_ECALL void EncParallelExecution(void* Args_)
{
    if (!oe_is_outside_enclave(Args_, sizeof(EncParallelExecutionArg)))
        return;

    EncParallelExecutionArg* argsHost = (EncParallelExecutionArg*)Args_;
    EncParallelExecutionArg args = *argsHost;

    if (!oe_is_outside_enclave((void*)args.counter, sizeof(unsigned)) ||
        !oe_is_outside_enclave((void*)args.release, sizeof(unsigned)))
        return;

    unsigned oldFlowId = PerThreadFlowId.GetU();
    if (oldFlowId)
    {
        printf(
            "%s(): Starting flow=%u, though thread already has %u\n",
            __FUNCTION__,
            args.flowId,
            oldFlowId);
        return;
    }
    PerThreadFlowId.Set(args.flowId);

    __atomic_add_fetch(args.counter, 1, __ATOMIC_SEQ_CST);
    while (!*args.release)
        ;

    oldFlowId = PerThreadFlowId.GetU();
    if (oldFlowId != args.flowId)
    {
        printf(
            "%s(): Stopping flow=%u, though overwritten with %u\n",
            __FUNCTION__,
            args.flowId,
            oldFlowId);
        return;
    }
    PerThreadFlowId.Set(0u);

    argsHost->result = OE_OK;
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

    EncTestCallHostFunctionArg* argsHost = (EncTestCallHostFunctionArg*)Args_;
    EncTestCallHostFunctionArg args = *argsHost;

    // Testing for a string to be outside the enclave is ugly. We might want
    // to provide a helper.
    if (!oe_is_outside_enclave(args.functionName, 1))
    {
        argsHost->result = OE_INVALID_PARAMETER;
        return;
    }

    argsHost->result = oe_call_host(args.functionName, NULL);
}

size_t Factor = 0;

OE_ECALL void EncCrossEnclaveCall(CrossEnclaveCallArg* arg)
{
    uint32_t myInput = arg->input;
    uint32_t myEnclaveId = arg->enclaveId;

    // Call next enclave via host.
    ++arg->input;
    ++arg->enclaveId;
    OE_TEST(oe_call_host("CrossEnclaveCall", arg) == OE_OK);

    // augment result with my result.
    uint32_t myResult = myInput * Factor;
    arg->output += myResult;
    printf(
        "enclave %u: Factor=%lu, myResult = %u, arg.output=%u\n",
        myEnclaveId,
        Factor,
        myResult,
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
