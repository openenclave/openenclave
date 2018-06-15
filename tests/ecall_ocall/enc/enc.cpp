// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#define OE_TRACE_LEVEL 1

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h> // for __oe_get_enclave_base()
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <mutex>
#include <system_error>
#include "../args.h"
#include "../crc32.h"
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

/*
  Recursion across boundary:

  Non-branched downwards recursion is simple, though want to avoid
  tail-recursion. So force post-OCall-work. Verify local state is preserved,
  across different recursion depths, and different degrees of parallelism.

  Rough concept:
  - hold some local (unique) state on the stack
  - perform OCall/ECall, massaging passed data
  - combine local state and returned data

  Using a hash-function and a unique flow/thread-id:
  - Outer function setting thread ID and start-value at host
  - Obtain local data by hashing a tag (start/end/host/enclave), flow-ID,
    recursion-level, and the current hash-value
  - Recurse, extending the hash-state
  - Then extend by local data and return the result

  This can also be done in parallel and with deterministic results.

  CRC32 as hash should suffice and has a simple-enough interface.
*/
OE_ECALL void EncRecursion(void* Args_)
{
    oe_result_t result = OE_OK;

    if (!oe_is_outside_enclave(Args_, sizeof(EncRecursionArg)))
        return;

    EncRecursionArg* args_host = (EncRecursionArg*)Args_;
    EncRecursionArg args = *args_host;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u/%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        EnclaveId,
        args.enclave_id,
        args.flow_id,
        args.recursions_left,
        args.crc);

    if (args.initial_count)
    {
        if (unsigned old_flow_id = PerThreadFlowId.GetU())
        {
            printf(
                "%s(): Starting flow=%u, though thread already has %u\n",
                __FUNCTION__,
                args.flow_id,
                old_flow_id);
            return;
        }
        PerThreadFlowId.Set(args.flow_id);
    }

    // catch initial state: Tag, Input-struct, EnclaveId, FlowId
    args.crc = Crc32::Hash(
        TAG_START_ENC,
        args,
        EnclaveId - args.enclave_id,
        PerThreadFlowId.GetU() - args.flow_id);
    args_host->crc = args.crc;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursions_left)
    {
        if (args.initial_count)
            args_host->initial_count = args.initial_count - 1;
        args_host->recursions_left = args.recursions_left - 1;
        result = oe_call_host("RecursionOcall", args_host);
    }

    // double-check FlowId is still intact and clobber it
    if (args.initial_count)
    {
        unsigned old_flow_id = PerThreadFlowId.GetU();
        if (old_flow_id != args.flow_id)
        {
            printf(
                "%s(): Stopping flow=%u, though overwritten with %u\n",
                __FUNCTION__,
                args.flow_id,
                old_flow_id);
            args.initial_count = 0;
        }
    }

    // catch output state: Tag + result + modified host-struct, original
    // input, and ID-diffs
    args_host->crc = Crc32::Hash(
        TAG_END_ENC,
        result,
        *args_host,
        args,
        EnclaveId - args.enclave_id,
        PerThreadFlowId.GetU() - args.flow_id);

    if (args.initial_count)
    {
        PerThreadFlowId.Set(0u);
    }
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
