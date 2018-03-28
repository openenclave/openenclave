// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <unistd.h>
#include <cassert>
#include <cassert>
#include <cstdio>
#include <cstdio>
#include <cstdlib>
#include <cstdlib>
#include <thread>
#include <vector>
#include "../../ecall_ocall/crc32.h"
#include "../args.h"

using namespace std;

#define THREAD_COUNT 5

void TestAbortStatus(OE_Enclave* enclave, const char* functionName)
{
    OE_Result result;
    Args args;
    args.ret = -1;

    printf("=== %s(%s)  \n", __FUNCTION__, functionName);
    result = OE_CallEnclave(enclave, functionName, &args);
    assert(result == OE_ENCLAVE_CRASHING);
    assert(args.ret == 0);
}

static void CrashEnclaveThread(
    OE_Enclave* enclave,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    OE_Result result;
    Args args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    // Wait all worker threads ready.
    while (*args.thread_ready_count != THREAD_COUNT - 1)
    {
        sleep(1);
    }

    // Crash the enclave to set enclave in abort status.
    result = OE_CallEnclave(enclave, "RegularAbort", &args);
    assert(result == OE_ENCLAVE_CRASHING);
    assert(args.ret == 0);

    // Release all worker threads.
    *args.is_enclave_crashed = 1;
    return;
}

static void EcallAfterCrashThread(
    OE_Enclave* enclave,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    OE_Result result;
    Args args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    __sync_fetch_and_add(args.thread_ready_count, 1);

    // Wait the enclave is aborted.
    while (*args.is_enclave_crashed == 0)
    {
        sleep(1);
    }

    // Try to ECALL into the enclave.
    result = OE_CallEnclave(enclave, "NormalECall", &args);
    assert(result == OE_ENCLAVE_CRASHING);
    assert(args.ret == -1);
    return;
}

static void OcallAfterCrashThread(
    OE_Enclave* enclave,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    OE_Result result;
    Args args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    result = OE_CallEnclave(enclave, "TestOCallAfterAbort", &args);
    assert(result == OE_OK);
    assert(args.ret == 0);

    return;
}

static uint32_t CalcRecursionHashHost(const EncRecursionArg* args_);
static uint32_t CalcRecursionHashEnc(const EncRecursionArg* args_);

// calc recursion hash locally, host part
static uint32_t CalcRecursionHashHost(const EncRecursionArg* args_)
{
    EncRecursionArg args = *args_;
    EncRecursionArg argsRec;
    OE_Result result = OE_OK;

    printf(
        "%s(): Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.flowId,
        args.recursionsLeft,
        args.crc);

    // catch initial state: Tag + Input-struct
    args.crc = Crc32::Hash(TAG_START_HOST, args);
    argsRec = args;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursionsLeft)
    {
        argsRec.recursionsLeft--;
        argsRec.crc = CalcRecursionHashEnc(&argsRec);
        if (argsRec.recursionsLeft)
        {
            if (argsRec.initialCount)
                argsRec.initialCount--;
            argsRec.recursionsLeft--;
        }
    }

    // catch output state: Tag + result + output, and again original input
    return Crc32::Hash(TAG_END_HOST, result, argsRec, args);
}

// calc recursion hash locally, enc part
static uint32_t CalcRecursionHashEnc(const EncRecursionArg* args_)
{
    EncRecursionArg args = *args_;
    EncRecursionArg argsHost;
    OE_Result result = OE_OK;

    printf(
        "%s(): Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.flowId,
        args.recursionsLeft,
        args.crc);

    // catch initial state: Tag + Input-structure.
    args.crc = Crc32::Hash(TAG_START_ENC, args);
    argsHost = args;

    if (args.recursionsLeft > 0)
    {
        if (argsHost.initialCount)
            argsHost.initialCount--;
        argsHost.recursionsLeft--;
        argsHost.crc = CalcRecursionHashHost(&argsHost);
    }

    // catch output state: Tag + result + modified host-struct, original
    // input.
    return Crc32::Hash(TAG_END_ENC, result, argsHost, args);
}

// Actual enclave/host/... recursion test. Trail of execution is gathered via
// Crc, success determined via comparison with separate, non-enclave version.
static uint32_t TestRecursion(
    OE_Enclave* enclave,
    unsigned flowId,
    unsigned recursionDepth,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    OE_Result result;
    EncRecursionArg args = {};

    printf(
        "%s(FlowId=%u, Recursions=%u)\n", __FUNCTION__, flowId, recursionDepth);

    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;
    args.enclave = enclave;
    args.flowId = flowId;
    args.recursionsLeft = recursionDepth;
    args.initialCount = 1;

    uint32_t crc = CalcRecursionHashEnc(&args);

    result = OE_CallEnclave(enclave, "EncRecursion", &args);
    assert(result == OE_OK);

    printf(
        "%s(FlowId=%u, RecursionDepth=%u): Expect CRC %#x, have "
        "CRC %#x, %s\n",
        __FUNCTION__,
        flowId,
        recursionDepth,
        crc,
        args.crc,
        (crc == args.crc) ? "MATCH" : "MISMATCH");

    assert(crc == args.crc);
    return crc;
}

// Ocall for recursion test
OE_OCALL void RecursionOcall(void* args_)
{
    OE_Result result = OE_OK;

    EncRecursionArg* argsPtr = (EncRecursionArg*)args_;
    EncRecursionArg args = *argsPtr;
    EncRecursionArg argsRec;

    printf(
        "%s(): Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.flowId,
        args.recursionsLeft,
        args.crc);

    // catch initial state: Tag + Input-struct
    args.crc = Crc32::Hash(TAG_START_HOST, args);
    argsRec = args;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursionsLeft)
    {
        argsRec.recursionsLeft--;
        result = OE_CallEnclave(
            (OE_Enclave*)argsRec.enclave, "EncRecursion", &argsRec);
    }
    else
    {
        __sync_fetch_and_add(args.thread_ready_count, 1);

        // Wait the enclave is aborted.
        while (*args.is_enclave_crashed == 0)
        {
            sleep(1);
        }

        // Verify the ECALL into the enclave will fail after enclave is aborted.
        assert(
            OE_CallEnclave(
                (OE_Enclave*)argsRec.enclave, "EncRecursion", NULL) ==
            OE_ENCLAVE_CRASHING);
    }

    // catch output state: Tag + result + output, and again original input
    argsPtr->crc = Crc32::Hash(TAG_END_HOST, result, argsRec, args);
}

// Test the regular abort case and un-handled hardware exception case in
// single thread.
static bool TestBasicAbort(const char* enclaveName)
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    const uint32_t flags = OE_GetCreateFlags();
    const char* functionNames[] = {"RegularAbort",
                                   "GenerateUnhandledHardwareException"};

    for (uint32_t i = 0; i < OE_COUNTOF(functionNames); i++)
    {
        if ((result = OE_CreateEnclave(enclaveName, flags, &enclave)) != OE_OK)
        {
            OE_PutErr("OE_CreateEnclave(): result=%u", result);
            return false;
        }

        // Skip the last test for simulation mode.
        if ((flags & OE_FLAG_SIMULATE) == 0 ||
            (i != OE_COUNTOF(functionNames) - 1))
        {
            TestAbortStatus(enclave, functionNames[i]);
        }

        if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
        {
            OE_PutErr("OE_TerminateEnclave(): result=%u", result);
            return false;
        }
    }

    return true;
}

// Test enclave abort status in multiple threads.
// Thread 1 -> abort the enclave when all other threads are ready.
// Thread 2 -> do a ECALL after thread 1 abort the enclave. The ECALL should
//  fail with abort status.
// Thread 3 -> do an OCALL after thread 1 abort the enclave. The OCALL should
//  fail with abort status.
// Thread 4 -> do a nested call, wait inside enclave, do an OCALL after thread
//  1 abort the enclave. The OCALL should fail with abort status, but exiting
//  ERET and ORET should return to enclave and host correctly.
// Thread 5 -> do a nested call, wait outside enclave, do an ECALL after thread
//  1 abort the enclave.The ECALL should fail with abort status, but exiting
//  ERET and ORET should return to enclave and host correctly.
static bool TestMultipleThreadAbort(const char* enclaveName)
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    // Create the enclave.
    const uint32_t flags = OE_GetCreateFlags();
    if ((result = OE_CreateEnclave(enclaveName, flags, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
        return false;
    }

    // Create threads.
    std::vector<std::thread> threads;
    uint32_t thread_ready_count = 0;
    uint32_t is_enclave_crashed = 0;

    threads.push_back(
        std::thread(
            CrashEnclaveThread,
            enclave,
            &thread_ready_count,
            &is_enclave_crashed));

    threads.push_back(
        std::thread(
            EcallAfterCrashThread,
            enclave,
            &thread_ready_count,
            &is_enclave_crashed));

    threads.push_back(
        std::thread(
            OcallAfterCrashThread,
            enclave,
            &thread_ready_count,
            &is_enclave_crashed));

    // Even recursion count will make the call end inside enclave, used to test
    // OCALL behavior.
    threads.push_back(
        std::thread(
            TestRecursion,
            enclave,
            1,
            32,
            &thread_ready_count,
            &is_enclave_crashed));

    // Even recursion count will make the call end in host side, used to test
    // ECALL behavior.
    threads.push_back(
        std::thread(
            TestRecursion,
            enclave,
            2,
            33,
            &thread_ready_count,
            &is_enclave_crashed));

    // All threads must exit gracefully.
    for (auto& t : threads)
    {
        t.join();
    }

    // Enclave should be terminated correctly.
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
        return false;
    }

    return true;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== This program is used to test enclave abort status.\n");

    if (TestBasicAbort(argv[1]))
    {
        printf("Basic abort status tests passed.\n");
    }
    else
    {
        OE_PutErr("Basic abort status tests failed.\n");
        return 1;
    }

    if (TestMultipleThreadAbort(argv[1]))
    {
        printf("Multiple threads abort status tests passed.\n");
    }
    else
    {
        OE_PutErr("Multiple threads abort status tests failed.\n");
        return 1;
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
