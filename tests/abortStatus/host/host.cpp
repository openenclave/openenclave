// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
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

void TestAbortStatus(oe_enclave_t* enclave, const char* functionName)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.divisor = 0;
    args.ret = -1;

    printf("=== %s(%s)  \n", __FUNCTION__, functionName);
    result = oe_call_enclave(enclave, functionName, &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == 0);
}

static void CrashEnclaveThread(
    oe_enclave_t* enclave,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    // Wait all worker threads ready.
    while (*args.thread_ready_count != THREAD_COUNT - 1)
    {
        sleep(1);
    }

    // Crash the enclave to set enclave in abort status.
    result = oe_call_enclave(enclave, "RegularAbort", &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == 0);

    // Release all worker threads.
    *args.is_enclave_crashed = 1;
    return;
}

static void EcallAfterCrashThread(
    oe_enclave_t* enclave,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    oe_result_t result;
    AbortStatusArgs args;
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
    result = oe_call_enclave(enclave, "NormalECall", &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == -1);
    return;
}

static void OcallAfterCrashThread(
    oe_enclave_t* enclave,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    oe_result_t result;
    AbortStatusArgs args;
    args.ret = -1;
    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;

    result = oe_call_enclave(enclave, "TestOCallAfterAbort", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.ret == 0);

    return;
}

static uint32_t CalcRecursionHashHost(const AbortStatusEncRecursionArg* args_);
static uint32_t CalcRecursionHashEnc(const AbortStatusEncRecursionArg* args_);

// calc recursion hash locally, host part
static uint32_t CalcRecursionHashHost(const AbortStatusEncRecursionArg* args_)
{
    AbortStatusEncRecursionArg args = *args_;
    AbortStatusEncRecursionArg argsRec;
    oe_result_t result = OE_OK;

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
static uint32_t CalcRecursionHashEnc(const AbortStatusEncRecursionArg* args_)
{
    AbortStatusEncRecursionArg args = *args_;
    AbortStatusEncRecursionArg argsHost;
    oe_result_t result = OE_OK;

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
    oe_enclave_t* enclave,
    unsigned flowId,
    unsigned recursionDepth,
    uint32_t* thread_ready_count,
    uint32_t* is_enclave_crashed)
{
    oe_result_t result;
    AbortStatusEncRecursionArg args = {};

    printf(
        "%s(FlowId=%u, Recursions=%u)\n", __FUNCTION__, flowId, recursionDepth);

    args.thread_ready_count = thread_ready_count;
    args.is_enclave_crashed = is_enclave_crashed;
    args.enclave = enclave;
    args.flowId = flowId;
    args.recursionsLeft = recursionDepth;
    args.initialCount = 1;

    uint32_t crc = CalcRecursionHashEnc(&args);

    result = oe_call_enclave(enclave, "EncRecursion", &args);
    OE_TEST(result == OE_OK);

    printf(
        "%s(FlowId=%u, RecursionDepth=%u): Expect CRC %#x, have "
        "CRC %#x, %s\n",
        __FUNCTION__,
        flowId,
        recursionDepth,
        crc,
        args.crc,
        (crc == args.crc) ? "MATCH" : "MISMATCH");

    OE_TEST(crc == args.crc);
    return crc;
}

// Ocall for recursion test
OE_OCALL void RecursionOcall(void* args_)
{
    oe_result_t result = OE_OK;

    AbortStatusEncRecursionArg* argsPtr = (AbortStatusEncRecursionArg*)args_;
    AbortStatusEncRecursionArg args = *argsPtr;
    AbortStatusEncRecursionArg argsRec;

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
        result = oe_call_enclave(
            (oe_enclave_t*)argsRec.enclave, "EncRecursion", &argsRec);
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
        OE_TEST(
            oe_call_enclave(
                (oe_enclave_t*)argsRec.enclave, "EncRecursion", NULL) ==
            OE_ENCLAVE_ABORTING);
    }

    // catch output state: Tag + result + output, and again original input
    argsPtr->crc = Crc32::Hash(TAG_END_HOST, result, argsRec, args);
}

// Test the regular abort case and un-handled hardware exception case in
// single thread.
static bool TestBasicAbort(const char* enclaveName)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    const uint32_t flags = oe_get_create_flags();
    const char* functionNames[] = {"RegularAbort",
                                   "GenerateUnhandledHardwareException"};

    for (uint32_t i = 0; i < OE_COUNTOF(functionNames); i++)
    {
        if ((result = oe_create_enclave(
                 enclaveName, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
        {
            oe_puterr("oe_create_enclave(): result=%u", result);
            return false;
        }

        // Skip the last test for simulation mode.
        if ((flags & OE_ENCLAVE_FLAG_SIMULATE) == 0 ||
            (i != OE_COUNTOF(functionNames) - 1))
        {
            TestAbortStatus(enclave, functionNames[i]);
        }

        if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        {
            oe_puterr("oe_terminate_enclave(): result=%u", result);
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
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    // Create the enclave.
    const uint32_t flags = oe_get_create_flags();
    if ((result = oe_create_enclave(
             enclaveName, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
        OE_OK)
    {
        oe_puterr("oe_create_enclave(): result=%u", result);
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
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_puterr("oe_terminate_enclave(): result=%u", result);
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
        oe_puterr("Basic abort status tests failed.\n");
        return 1;
    }

    if (TestMultipleThreadAbort(argv[1]))
    {
        printf("Multiple threads abort status tests passed.\n");
    }
    else
    {
        oe_puterr("Multiple threads abort status tests failed.\n");
        return 1;
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
