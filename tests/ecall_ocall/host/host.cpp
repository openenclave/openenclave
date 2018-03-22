// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include <assert.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <system_error>
#include <thread>
#include <vector>
#include "../args.h"
#include "../crc32.h"

#define THREAD_COUNT 5 // must not exceed what is configured in sign.conf

// Slighly specialized wrapper around an OE_Enclave object to allow
// scope-based lifetime mgmt. Also a bit of identifying glue (which relies on
// custom code in the enclave).
struct EnclaveWrap
{
    EnclaveWrap(const char* EnclavePath, uint32_t Flags)
    {
        EncSetEnclaveIdArg args = {};
        OE_Enclave* enclave;
        OE_Result result;

        if ((result = OE_CreateEnclave(EnclavePath, Flags, &enclave)) != OE_OK)
        {
            OE_PutErr("OE_CreateEnclave(): result=%u", result);
            throw std::runtime_error("OE_CreateEnclave() failed");
        }
        m_Id = m_Enclaves.size();

        args.result = OE_FAILURE;
        args.id = m_Id;
        if ((result = OE_CallEnclave(enclave, "EncSetEnclaveId", &args)) !=
            OE_OK)
        {
            OE_PutErr("OE_CallEnclave(EncSetEnclaveId): result=%u", result);
            throw std::runtime_error("OE_CallEnclave(EncSetEnclaveId) failed");
        }
        if (args.result != OE_OK)
        {
            OE_PutErr("EncSetEnclaveId(): result=%u", result);
            throw std::runtime_error("EncSetEnclaveId() failed");
        }

        m_EnclaveBase = args.baseAddr;
        m_Enclaves.push_back(enclave);
    }

    ~EnclaveWrap()
    {
        OE_Result result;
        if ((result = OE_TerminateEnclave(Get())) != OE_OK)
        {
            OE_PutErr("OE_TerminateEnclave(): result=%u", result);
        }
        // simplified cleanup to keep identifiers stable
        m_Enclaves[m_Id] = NULL;
    }

    unsigned GetId() const
    {
        return m_Id;
    }
    const void* GetBase() const
    {
        return m_EnclaveBase;
    }
    OE_Enclave* Get() const
    {
        return m_Enclaves[m_Id];
    }

    static OE_Enclave* Get(unsigned Id)
    {
        return m_Enclaves[Id];
    }

  private:
    unsigned m_Id;
    const void* m_EnclaveBase;
    static std::vector<OE_Enclave*> m_Enclaves;
};
std::vector<OE_Enclave*> EnclaveWrap::m_Enclaves;

static std::vector<void*> InitOCallValues;

// OCall handler for initial ocall testing - track argument for later
// verification
OE_OCALL void InitOcallHandler(void* Arg_)
{
    InitOCallValues.push_back(Arg_);
}

// Initial OCall test helper - Verify that the ocall happened (by asking the
// enclave), and obtain the result of it.
static void TestInitOcallResult(unsigned EnclaveId)
{
    OE_Result result, resultOcall;

    resultOcall = OE_FAILURE;
    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "EncGetInitOcallResult", &resultOcall);
    assert(result == OE_OK);
    assert(resultOcall == OE_OK);
}

// For ocall-test on not explicitly OE_OCALL-tagged function
extern "C" void DummyHostFunction(void*)
{
}

// Test availability and non-availability of functions, according to their
// OE_OCALL/OE_ECALL annotations.
static void TestInvalidFunctions(unsigned EnclaveId)
{
    OE_Result result;
    EncTestNonExistingFunctionArg args = {};

    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "EncDummyEncFunction", NULL);
    printf("OE_CallEnclave(EncDummyEncFunction): %u\n", result);
    assert(result == OE_OK);

    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "EncUnExportedFunction", NULL);
    printf("OE_CallEnclave(EncUnExportedFunction): %u\n", result);
    assert(result == OE_NOT_FOUND);

    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "NonExistingFunction", NULL);
    printf("OE_CallEnclave(NonExistingFunction): %u\n", result);
    assert(result == OE_NOT_FOUND);

    args.result = OE_FAILURE;
    args.functionName = "DummyHostFunction";
    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "EncTestNonExistingFunction", &args);
    printf(
        "OE_CallEnclave(EncTestNonExistingFunction, DummyHostFunction): "
        "%u/%u\n",
        result,
        args.result);
    assert(result == OE_OK);
    assert(args.result == OE_OK); // See #137, intended?

    args.result = OE_FAILURE;
    args.functionName = "NonExistingFunction";
    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "EncTestNonExistingFunction", &args);
    printf(
        "OE_CallEnclave(EncTestNonExistingFunction, NonExistingFunction): "
        "%u/%u\n",
        result,
        args.result);
    assert(result == OE_OK);
    assert(args.result == OE_NOT_FOUND);
}

// Helper function for parallel test
static void ParallelThread(
    unsigned EnclaveId,
    unsigned FlowId,
    volatile unsigned* Counter,
    volatile unsigned* Release)
{
    OE_Result result;

    EncParallelExecutionArg args = {};
    args.result = OE_FAILURE;
    args.enclaveId = EnclaveId;
    args.flowId = FlowId;
    args.counter = Counter;
    args.release = Release;

    OE_TRACE_INFO(
        "%s(Enclave=%u, Flow=%u) started\n", __FUNCTION__, EnclaveId, FlowId);
    result = OE_CallEnclave(
        EnclaveWrap::Get(EnclaveId), "EncParallelExecution", &args);
    OE_TRACE_INFO(
        "%s(Enclave=%u, Flow=%u) done.\n", __FUNCTION__, EnclaveId, FlowId);
    assert(result == OE_OK);
    assert(args.result == OE_OK);
}

// Parallel execution test - verify parallel threads are actually executed
static void TestExecutionParallel(
    std::vector<unsigned> EnclaveIds,
    unsigned ThreadCount)
{
    std::vector<std::thread> threads;
    volatile unsigned counter = 0;
    volatile unsigned release = 0;

    printf("%s(): Test parallel execution across enclaves {", __FUNCTION__);
    for (unsigned e : EnclaveIds)
        printf("%u ", e);
    printf("} with %u threads each\n", ThreadCount);

    counter = release = 0;

    for (unsigned enclaveId : EnclaveIds)
    {
        for (unsigned i = 0; i < ThreadCount; i++)
        {
            threads.push_back(
                std::thread(
                    ParallelThread, enclaveId, i + 1, &counter, &release));
        }
    }

    // wait for all enclave-threads to have incremented the counter
    while (counter < EnclaveIds.size() * ThreadCount)
    {
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)

        static unsigned oldVal;
        if (counter != oldVal)
        {
            printf(
                "%s(): Looking for counter=%u, have %u.\n",
                __FUNCTION__,
                (unsigned)EnclaveIds.size() * ThreadCount,
                counter);
            oldVal = counter;
        }
#endif
    }

    // all threads arrived and spin on the release
    release = 1;

    for (auto& t : threads)
    {
        t.join();
    }
}

static std::set<unsigned> RotatingEnclaveIds;

// Ocall for recursion test
OE_OCALL void RecursionOcall(void* Args_)
{
    OE_Result result = OE_OK;

    EncRecursionArg* argsPtr = (EncRecursionArg*)Args_;
    EncRecursionArg args = *argsPtr;
    EncRecursionArg argsRec;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.enclaveId,
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
        if (argsRec.isRotatingEnclave)
        {
            std::set<unsigned>::iterator it =
                RotatingEnclaveIds.find(args.enclaveId);
            assert(it != RotatingEnclaveIds.end());
            if (++it == RotatingEnclaveIds.end())
            {
                it = RotatingEnclaveIds.begin();
            }
            argsRec.enclaveId = *it;
        }
        result = OE_CallEnclave(
            EnclaveWrap::Get(argsRec.enclaveId), "EncRecursion", &argsRec);
    }

    // catch output state: Tag + result + output, and again original input
    argsPtr->crc = Crc32::Hash(TAG_END_HOST, result, argsRec, args);
}

static uint32_t CalcRecursionHashHost(const EncRecursionArg* Args);
static uint32_t CalcRecursionHashEnc(const EncRecursionArg* Args);

// calc recursion hash locally, host part
static uint32_t CalcRecursionHashHost(const EncRecursionArg* Args)
{
    EncRecursionArg args = *Args;
    EncRecursionArg argsRec;
    OE_Result result = OE_OK;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.enclaveId,
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
        if (argsRec.isRotatingEnclave)
        {
            std::set<unsigned>::iterator it =
                RotatingEnclaveIds.find(args.enclaveId);
            assert(it != RotatingEnclaveIds.end());
            if (++it == RotatingEnclaveIds.end())
            {
                it = RotatingEnclaveIds.begin();
            }
            argsRec.enclaveId = *it;
        }

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
static uint32_t CalcRecursionHashEnc(const EncRecursionArg* Args)
{
    EncRecursionArg args = *Args;
    EncRecursionArg argsHost;
    OE_Result result = OE_OK;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.enclaveId,
        args.flowId,
        args.recursionsLeft,
        args.crc);

    // catch initial state: Tag + Input-struct + EnclaveId
    args.crc = Crc32::Hash(TAG_START_ENC, args, 0u, 0u);
    argsHost = args;

    if (args.recursionsLeft > 0)
    {
        if (argsHost.initialCount)
            argsHost.initialCount--;
        argsHost.recursionsLeft--;
        argsHost.crc = CalcRecursionHashHost(&argsHost);
    }

    // catch output state: Tag + result + modified host-struct, original
    // input, and ID-diffs
    return Crc32::Hash(TAG_END_ENC, result, argsHost, args, 0u, 0u);
}

// Actual enclave/host/... recursion test. Trail of execution is gathered via
// Crc, success determined via comparison with separate, non-enclave version.
static uint32_t TestRecursion(
    size_t EnclaveId,
    unsigned FlowId,
    unsigned RecursionDepth)
{
    OE_Result result;
    EncRecursionArg args = {};

    OE_TRACE_INFO(
        "%s(EnclaveId=%lu, FlowId=%u, Recursions=%u)\n",
        __FUNCTION__,
        EnclaveId,
        FlowId,
        RecursionDepth);

    args.enclaveId = EnclaveId;
    args.flowId = FlowId;
    args.recursionsLeft = RecursionDepth;
    args.initialCount = 1;

    uint32_t crc = CalcRecursionHashEnc(&args);

    result = OE_CallEnclave(EnclaveWrap::Get(EnclaveId), "EncRecursion", &args);
    assert(result == OE_OK);

    printf(
        "%s(EnclaveId=%lu, FlowId=%u, RecursionDepth=%u): Expect CRC %#x, have "
        "CRC %#x, %s\n",
        __FUNCTION__,
        EnclaveId,
        FlowId,
        RecursionDepth,
        crc,
        args.crc,
        (crc == args.crc) ? "MATCH" : "MISMATCH");
    assert(crc == args.crc);
    return crc;
}

// Thread helper to perform recursion tests in parallel across multiple threads.
static void RecursionThread(
    unsigned EnclaveId,
    bool RotateEnclaves,
    unsigned FlowId,
    unsigned RecursionDepth,
    unsigned LoopCount,
    uint32_t ExpectedCrc)
{
    // a barrier would be nice here, though we have no support in gcc yet.
    for (unsigned l = 0; l < LoopCount; l++)
    {
        OE_Result result;
        EncRecursionArg args = {};

        args.enclaveId = EnclaveId;
        args.flowId = FlowId;
        args.recursionsLeft = RecursionDepth;
        args.initialCount = RotateEnclaves ? RotatingEnclaveIds.size() : 1;
        args.isRotatingEnclave = !!RotateEnclaves;

        result =
            OE_CallEnclave(EnclaveWrap::Get(EnclaveId), "EncRecursion", &args);
        assert(result == OE_OK);
        assert(args.crc == ExpectedCrc);
    }
}

// Parallel recursion test.
static void TestRecursionParallel(
    std::vector<unsigned> EnclaveIds,
    unsigned ThreadCount,
    unsigned RecursionDepth,
    unsigned LoopCount)
{
    std::vector<std::thread> threads;
    std::map<unsigned, std::vector<uint32_t>> expectedCrcs;

    printf("%s(): Test recursion w/ multiple enclaves {", __FUNCTION__);
    for (unsigned e : EnclaveIds)
        printf("%u ", e);
    printf(
        "} with %u threads each, rec-depth %u, loop-count %u\n",
        ThreadCount,
        RecursionDepth,
        LoopCount);

    // Precalc Crcs
    for (unsigned enclaveId : EnclaveIds)
    {
        for (unsigned i = 0; i < ThreadCount; i++)
        {
            EncRecursionArg args = {};
            args.enclaveId = enclaveId;
            args.flowId = i + 1;
            args.recursionsLeft = RecursionDepth + i;
            args.initialCount = 1;

            expectedCrcs[enclaveId].push_back(CalcRecursionHashEnc(&args));
        }
    }

    for (unsigned enclaveId : EnclaveIds)
    {
        for (unsigned i = 0; i < ThreadCount; i++)
        {
            threads.push_back(
                std::thread(
                    RecursionThread,
                    enclaveId,
                    false,
                    i + 1,
                    RecursionDepth + i,
                    LoopCount,
                    expectedCrcs[enclaveId][i]));
        }
    }

    for (auto& t : threads)
    {
        t.join();
    }
}

// Parallel recursion test, across threads
static void TestRecursionCrossEnclave(
    std::vector<unsigned> EnclaveIds,
    unsigned ThreadCount,
    unsigned RecursionDepth,
    unsigned LoopCount)
{
    std::vector<std::thread> threads;
    std::vector<unsigned> expectedCrcs;

    printf("%s(): Test recursion across enclaves {", __FUNCTION__);
    for (unsigned e : EnclaveIds)
        printf("%u ", e);
    printf(
        "} with %u threads total, rec-depth %u, loop-count %u\n",
        ThreadCount,
        RecursionDepth,
        LoopCount);

    RotatingEnclaveIds.clear();
    for (unsigned enclaveId : EnclaveIds)
        RotatingEnclaveIds.insert(enclaveId);

    // Precalc Crcs
    for (unsigned i = 0; i < ThreadCount; i++)
    {
        EncRecursionArg args = {};
        args.enclaveId = EnclaveIds[i % EnclaveIds.size()];
        args.flowId = i + 1;
        args.recursionsLeft = RecursionDepth + i;
        args.initialCount = EnclaveIds.size();
        args.isRotatingEnclave = 1;

        expectedCrcs.push_back(CalcRecursionHashEnc(&args));
    }

    for (unsigned i = 0; i < ThreadCount; i++)
    {
        threads.push_back(
            std::thread(
                RecursionThread,
                EnclaveIds[i % EnclaveIds.size()],
                true,
                i + 1,
                RecursionDepth + i,
                LoopCount,
                expectedCrcs[i]));
    }

    for (auto& t : threads)
    {
        t.join();
    }

    RotatingEnclaveIds.clear();
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();

    assert(InitOCallValues.size() == 0);
    EnclaveWrap enc1(argv[1], flags);
    // verify initial OCall succeeded
    assert(InitOCallValues.size() == 1);
    assert(InitOCallValues[0] != NULL);
    assert(InitOCallValues[0] == enc1.GetBase());
    TestInitOcallResult(enc1.GetId());

    // invalid function tests
    TestInvalidFunctions(enc1.GetId());

    // verify threads execute in parallel
    TestExecutionParallel({enc1.GetId()}, THREAD_COUNT);

    // serial recursion tests.
    assert(TestRecursion(enc1.GetId(), 1, 33) == 0xb6b66b4d);
    assert(TestRecursion(enc1.GetId(), 2, 33) == 0x721ea484);
    assert(TestRecursion(enc1.GetId(), 3, 100) == 0x83fab7f6);

    // Test in a 2nd enclave
    EnclaveWrap enc2(argv[1], flags);
    // verify initial OCall succeeded
    assert(InitOCallValues.size() == 2);
    assert(InitOCallValues[1] != NULL);
    assert(InitOCallValues[1] != InitOCallValues[0]);
    assert(InitOCallValues[1] == enc2.GetBase());
    TestInitOcallResult(enc2.GetId());

    // verify threads execute in parallel across enclaves
    TestExecutionParallel({enc1.GetId(), enc2.GetId()}, THREAD_COUNT);

    // verify recursion in 2nd enclave by itself
    assert(TestRecursion(enc2.GetId(), 1, 33) == 0xf3d31c55);

    // Test parallel recursion in one enclave
    TestRecursionParallel({enc1.GetId()}, THREAD_COUNT, 100, 3000);

    // And parallel with multiple enclaves
    TestRecursionParallel(
        {enc1.GetId(), enc2.GetId()}, THREAD_COUNT, 20, 10000);

    // Parallel across enclaves. Leave one thread unused to stir things, add
    // yet another enclave.
    EnclaveWrap enc3(argv[1], flags);

    TestRecursionCrossEnclave(
        {enc1.GetId(), enc2.GetId(), enc3.GetId()}, THREAD_COUNT - 1, 20, 1000);

    return 0;
}
