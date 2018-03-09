// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h> // for __OE_GetEnclaveBase()
#include <openenclave/enclave.h>
#include <stdio.h>
#include <mutex>
#include <system_error>
#include "../args.h"
#include "../crc32.h"
#include "helpers.h"

unsigned EnclaveId = ~0u;

static TLSWrapper PerThreadFlow;

// class to verify OCalls in static Initializers
struct StaticInitOcaller
{
    StaticInitOcaller() : m_Result(OE_FAILURE)
    {
        m_Result =
            OE_CallHost("InitOcallHandler", (void*)__OE_GetEnclaveBase());
        OE_Assert(m_Result == OE_OK);
    }
    OE_Result GetOcallResult() const
    {
        return m_Result;
    }

  private:
    OE_Result m_Result;
} StaticInitOcaller_;

// obtain static init ocall result
OE_ECALL void EncGetInitOcallResult(void* Args_)
{
    if (!OE_IsOutsideEnclave(Args_, sizeof(OE_Result)))
        return;

    OE_Result* result = (OE_Result*)Args_;
    *result = StaticInitOcaller_.GetOcallResult();
}

// Set custom enclave ID for later tracking
OE_ECALL void EncSetEnclaveId(void* Args_)
{
    if (!OE_IsOutsideEnclave(Args_, sizeof(TestEcallOcallSetEncIdArg)))
        return;

    TestEcallOcallSetEncIdArg* argsHost = (TestEcallOcallSetEncIdArg*)Args_;
    TestEcallOcallSetEncIdArg args = *argsHost;

    if (EnclaveId != ~0u)
    {
        argsHost->Result = OE_INVALID_PARAMETER;
    }
    EnclaveId = args.Id;
    argsHost->BaseAddr = __OE_GetEnclaveBase();
    argsHost->Result = OE_OK;
}

// Parallel execution test. Using a (trivialized) barrier in the host,
// spin-wait until all expected threads reach it, w/o performing an ocall.
OE_ECALL void EncParallelExecution(void* Args_)
{
    if (!OE_IsOutsideEnclave(Args_, sizeof(TestEcallOcallParArg)))
        return;

    TestEcallOcallParArg* argsHost = (TestEcallOcallParArg*)Args_;
    TestEcallOcallParArg args = *argsHost;

    if (!OE_IsOutsideEnclave((void*)args.Counter, sizeof(unsigned)) ||
        !OE_IsOutsideEnclave((void*)args.Release, sizeof(unsigned)))
        return;

    unsigned oldFlowId = PerThreadFlow.GetU();
    if (oldFlowId)
    {
        printf(
            "%s(): Starting flow=%u, though thread already has %u\n",
            __FUNCTION__,
            args.FlowId,
            oldFlowId);
        return;
    }
    PerThreadFlow.Set(args.FlowId);

    __atomic_add_fetch(args.Counter, 1, __ATOMIC_SEQ_CST);
    while (!*args.Release)
        ;

    oldFlowId = PerThreadFlow.GetU();
    if (oldFlowId != args.FlowId)
    {
        printf(
            "%s(): Stopping flow=%u, though overwritten with %u\n",
            __FUNCTION__,
            args.FlowId,
            oldFlowId);
        return;
    }
    PerThreadFlow.Set(0u);

    argsHost->Result = OE_OK;
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
    OE_Result result = OE_OK;

    if (!OE_IsOutsideEnclave(Args_, sizeof(TestEcallOcallRecArg)))
        return;

    TestEcallOcallRecArg* argsHost = (TestEcallOcallRecArg*)Args_;
    TestEcallOcallRecArg args = *argsHost;

    // printf("%s(): Flow=%u, recLeft=%u, inCrc=%#x\n",
    //    __FUNCTION__, args.FlowId, args.RecursionsLeft, args.Crc);

    if (args.IsInitial)
    {
        if (unsigned oldFlowId = PerThreadFlow.GetU())
        {
            printf(
                "%s(): Starting flow=%u, though thread already has %u\n",
                __FUNCTION__,
                args.FlowId,
                oldFlowId);
            return;
        }
        PerThreadFlow.Set(args.FlowId);
    }

    // catch initial state: Tag, Input-struct, EnclaveId, FlowId
    {
        Crc32 crc(TAG_START_ENC);
        crc(args);
        crc(EnclaveId - args.EnclaveNr);
        crc(PerThreadFlow.GetU() - args.FlowId);
        args.Crc = crc();
    }
    argsHost->Crc = args.Crc;

    // recurse as needed, passing initial-state-crc as input
    if (args.RecursionsLeft)
    {
        argsHost->IsInitial = 0;
        argsHost->RecursionsLeft = args.RecursionsLeft - 1;
        result = OE_CallHost("RecursionOcall", argsHost);
    }

    // double-check FlowId is still intact and clobber it
    if (args.IsInitial)
    {
        unsigned oldFlowId = PerThreadFlow.GetU();
        if (oldFlowId != args.FlowId)
        {
            printf(
                "%s(): Stopping flow=%u, though overwritten with %u\n",
                __FUNCTION__,
                args.FlowId,
                oldFlowId);
            args.IsInitial = 0;
        }
    }

    // catch output state: Tag + result + modified host-struct
    Crc32 crc(TAG_END_ENC);
    crc(result);
    crc(*argsHost);

    // and extend by original input and ID-diffs
    crc(args);
    crc(EnclaveId - args.EnclaveNr);
    crc(PerThreadFlow.GetU() - args.FlowId);

    if (args.IsInitial)
    {
        PerThreadFlow.Set(0u);
    }

    argsHost->Crc = crc();
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
OE_ECALL void EncTestNonExistingFunction(void* Args_)
{
    if (!OE_IsOutsideEnclave(Args_, sizeof(TestEcallOcallNAArg)))
        return;

    TestEcallOcallNAArg* argsHost = (TestEcallOcallNAArg*)Args_;
    TestEcallOcallNAArg args = *argsHost;

    // Testing for a string to be outside the enclave is ugly. We might want
    // to provide a helper.
    if (!OE_IsOutsideEnclave(args.FunctionName, 1))
    {
        argsHost->Result = OE_INVALID_PARAMETER;
        return;
    }

    argsHost->Result = OE_CallHost(args.FunctionName, NULL);
}
