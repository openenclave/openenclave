// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
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

// Slightly specialized wrapper around an oe_enclave_t object to allow
// scope-based lifetime mgmt. Also a bit of identifying glue (which relies on
// custom code in the enclave).
struct EnclaveWrap
{
    EnclaveWrap(const char* enclave_path, uint32_t flags)
    {
        EncSetEnclaveIdArg args = {};
        oe_enclave_t* enclave;
        oe_result_t result;

        if ((result = oe_create_enclave(
                 enclave_path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
        {
            oe_put_err("oe_create_enclave(): result=%u", result);
            throw std::runtime_error("oe_create_enclave() failed");
        }
        m_id = m_enclaves.size();

        args.result = OE_FAILURE;
        args.id = m_id;
        if ((result = oe_call_enclave(enclave, "EncSetEnclaveId", &args)) !=
            OE_OK)
        {
            oe_put_err("oe_call_enclave(EncSetEnclaveId): result=%u", result);
            throw std::runtime_error("oe_call_enclave(EncSetEnclaveId) failed");
        }
        if (args.result != OE_OK)
        {
            oe_put_err("EncSetEnclaveId(): result=%u", result);
            throw std::runtime_error("EncSetEnclaveId() failed");
        }

        m_enclave_base = args.base_addr;
        m_enclaves.push_back(enclave);
    }

    ~EnclaveWrap()
    {
        oe_result_t result;
        if ((result = oe_terminate_enclave(Get())) != OE_OK)
        {
            oe_put_err("oe_terminate_enclave(): result=%u", result);
        }
        // simplified cleanup to keep identifiers stable
        m_enclaves[m_id] = NULL;
    }

    unsigned GetId() const
    {
        return m_id;
    }
    const void* GetBase() const
    {
        return m_enclave_base;
    }
    oe_enclave_t* Get() const
    {
        return m_enclaves[m_id];
    }

    static oe_enclave_t* Get(unsigned Id)
    {
        return m_enclaves[Id];
    }

  private:
    unsigned m_id;
    const void* m_enclave_base;
    static std::vector<oe_enclave_t*> m_enclaves;
};
std::vector<oe_enclave_t*> EnclaveWrap::m_enclaves;

static std::vector<void*> InitOCallValues;

// OCall handler for initial ocall testing - track argument for later
// verification
OE_OCALL void InitOcallHandler(void* arg_)
{
    InitOCallValues.push_back(arg_);
}

// Initial OCall test helper - Verify that the ocall happened (by asking the
// enclave), and obtain the result of it.
static void TestInitOcallResult(unsigned enclave_id)
{
    oe_result_t result, result_ocall;

    result_ocall = OE_FAILURE;
    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncGetInitOcallResult", &result_ocall);
    OE_TEST(result == OE_OK);
    OE_TEST(result_ocall == OE_OK);
}

// For ocall-test on not explicitly OE_OCALL-tagged function
#if defined(__unix__)
extern "C" void ExportedHostFunction(void*)
#elif defined(_WIN32)
extern "C" OE_EXPORT void ExportedHostFunction(void*)
#endif
{
}

#if defined(_WIN32)
extern "C" void InternalHostFunction(void*)
{
}
#else
extern "C" void __attribute__((visibility("internal")))
InternalHostFunction(void*)
{
}
#endif

// Test availability and non-availability of functions, according to their
// OE_OCALL/OE_ECALL annotations.
static void TestInvalidFunctions(unsigned enclave_id)
{
    oe_result_t result;
    EncTestCallHostFunctionArg args = {};

    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncDummyEncFunction", NULL);
    printf("oe_call_enclave(EncDummyEncFunction): %u\n", result);
    OE_TEST(result == OE_OK);

    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncUnExportedFunction", NULL);
    printf("oe_call_enclave(EncUnExportedFunction): %u\n", result);
    OE_TEST(result == OE_NOT_FOUND);

    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "NonExistingFunction", NULL);
    printf("oe_call_enclave(NonExistingFunction): %u\n", result);
    OE_TEST(result == OE_NOT_FOUND);

    args.result = OE_FAILURE;
    args.function_name = "InternalHostFunction";
    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncTestCallHostFunction", &args);
    printf(
        "oe_call_enclave(EncTestCallHostFunction, InternalHostFunction): "
        "%u/%u\n",
        result,
        args.result);
    OE_TEST(result == OE_OK);
    OE_TEST(args.result == OE_NOT_FOUND);

    args.result = OE_FAILURE;
    args.function_name = "NonExistingFunction";
    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncTestCallHostFunction", &args);
    printf(
        "oe_call_enclave(EncTestCallHostFunction, NonExistingFunction): "
        "%u/%u\n",
        result,
        args.result);
    OE_TEST(result == OE_OK);
    OE_TEST(args.result == OE_NOT_FOUND);

    args.result = OE_FAILURE;
    args.function_name = "ExportedHostFunction";
    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncTestCallHostFunction", &args);
    printf(
        "oe_call_enclave(EncTestCallHostFunction, ExportedHostFunction): "
        "%u/%u\n",
        result,
        args.result);
    OE_TEST(result == OE_OK);
    OE_TEST(args.result == OE_OK);
}

// Helper function for parallel test
static void ParallelThread(
    unsigned enclave_id,
    unsigned flow_id,
    volatile unsigned* counter,
    volatile unsigned* release)
{
    oe_result_t result;

    EncParallelExecutionArg args = {};
    args.result = OE_FAILURE;
    args.enclave_id = enclave_id;
    args.flow_id = flow_id;
    args.counter = counter;
    args.release = release;

    OE_TRACE_INFO(
        "%s(Enclave=%u, Flow=%u) started\n", __FUNCTION__, enclave_id, flow_id);
    result = oe_call_enclave(
        EnclaveWrap::Get(enclave_id), "EncParallelExecution", &args);
    OE_TRACE_INFO(
        "%s(Enclave=%u, Flow=%u) done.\n", __FUNCTION__, enclave_id, flow_id);
    OE_TEST(result == OE_OK);
    OE_TEST(args.result == OE_OK);
}

// Parallel execution test - verify parallel threads are actually executed
static void TestExecutionParallel(
    std::vector<unsigned> enclave_ids,
    unsigned thread_count)
{
    std::vector<std::thread> threads;
    volatile unsigned counter = 0;
    volatile unsigned release = 0;

    printf("%s(): Test parallel execution across enclaves {", __FUNCTION__);
    for (unsigned e : enclave_ids)
        printf("%u ", e);
    printf("} with %u threads each\n", thread_count);

    counter = release = 0;

    for (unsigned enclave_id : enclave_ids)
    {
        for (unsigned i = 0; i < thread_count; i++)
        {
            threads.push_back(
                std::thread(
                    ParallelThread, enclave_id, i + 1, &counter, &release));
        }
    }

    // wait for all enclave-threads to have incremented the counter
    while (counter < enclave_ids.size() * thread_count)
    {
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)

        static unsigned old_val;
        if (counter != old_val)
        {
            printf(
                "%s(): Looking for counter=%u, have %u.\n",
                __FUNCTION__,
                (unsigned)EnclaveIds.size() * thread_count,
                counter);
            old_val = counter;
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

static std::set<unsigned> g_rotating_enclave_ids;

// Ocall for recursion test
OE_OCALL void RecursionOcall(void* args_)
{
    oe_result_t result = OE_OK;

    EncRecursionArg* args_ptr = (EncRecursionArg*)args_;
    EncRecursionArg args = *args_ptr;
    EncRecursionArg args_rec;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.enclave_id,
        args.flow_id,
        args.recursions_left,
        args.crc);

    // catch initial state: Tag + Input-struct
    args.crc = Crc32::Hash(TAG_START_HOST, args);
    args_rec = args;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursions_left)
    {
        args_rec.recursions_left--;
        if (args_rec.is_rotating_enclave)
        {
            std::set<unsigned>::iterator it =
                g_rotating_enclave_ids.find(args.enclave_id);
            OE_TEST(it != g_rotating_enclave_ids.end());
            if (++it == g_rotating_enclave_ids.end())
            {
                it = g_rotating_enclave_ids.begin();
            }
            args_rec.enclave_id = *it;
        }
        result = oe_call_enclave(
            EnclaveWrap::Get(args_rec.enclave_id), "EncRecursion", &args_rec);
    }

    // catch output state: Tag + result + output, and again original input
    args_ptr->crc = Crc32::Hash(TAG_END_HOST, result, args_rec, args);
}

static uint32_t CalcRecursionHashHost(const EncRecursionArg* args_);
static uint32_t CalcRecursionHashEnc(const EncRecursionArg* args_);

// calc recursion hash locally, host part
static uint32_t CalcRecursionHashHost(const EncRecursionArg* args_)
{
    EncRecursionArg args = *args_;
    EncRecursionArg args_rec;
    oe_result_t result = OE_OK;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.enclave_id,
        args.flow_id,
        args.recursions_left,
        args.crc);

    // catch initial state: Tag + Input-struct
    args.crc = Crc32::Hash(TAG_START_HOST, args);
    args_rec = args;

    // recurse as needed, passing initial-state-crc as input
    if (args.recursions_left)
    {
        args_rec.recursions_left--;
        if (args_rec.is_rotating_enclave)
        {
            std::set<unsigned>::iterator it =
                g_rotating_enclave_ids.find(args.enclave_id);
            OE_TEST(it != g_rotating_enclave_ids.end());
            if (++it == g_rotating_enclave_ids.end())
            {
                it = g_rotating_enclave_ids.begin();
            }
            args_rec.enclave_id = *it;
        }

        args_rec.crc = CalcRecursionHashEnc(&args_rec);
        if (args_rec.recursions_left)
        {
            if (args_rec.initial_count)
                args_rec.initial_count--;
            args_rec.recursions_left--;
        }
    }

    // catch output state: Tag + result + output, and again original input
    return Crc32::Hash(TAG_END_HOST, result, args_rec, args);
}

// calc recursion hash locally, enc part
static uint32_t CalcRecursionHashEnc(const EncRecursionArg* args_)
{
    EncRecursionArg args = *args_;
    EncRecursionArg args_host;
    oe_result_t result = OE_OK;

    OE_TRACE_INFO(
        "%s(): EnclaveId=%u, Flow=%u, recLeft=%u, inCrc=%#x\n",
        __FUNCTION__,
        args.enclave_id,
        args.flow_id,
        args.recursions_left,
        args.crc);

    // catch initial state: Tag + Input-struct + enclave_id
    args.crc = Crc32::Hash(TAG_START_ENC, args, 0u, 0u);
    args_host = args;

    if (args.recursions_left > 0)
    {
        if (args_host.initial_count)
            args_host.initial_count--;
        args_host.recursions_left--;
        args_host.crc = CalcRecursionHashHost(&args_host);
    }

    // catch output state: Tag + result + modified host-struct, original
    // input, and ID-diffs
    return Crc32::Hash(TAG_END_ENC, result, args_host, args, 0u, 0u);
}

// Actual enclave/host/... recursion test. Trail of execution is gathered via
// Crc, success determined via comparison with separate, non-enclave version.
static uint32_t TestRecursion(
    size_t enclave_id,
    unsigned flow_id,
    unsigned recursion_depth)
{
    oe_result_t result;
    EncRecursionArg args = {};

    OE_TRACE_INFO(
        "%s(EnclaveId=%llu, FlowId=%u, Recursions=%u)\n",
        __FUNCTION__,
        OE_LLU(enclave_id),
        flow_id,
        recursion_depth);

    args.enclave_id = enclave_id;
    args.flow_id = flow_id;
    args.recursions_left = recursion_depth;
    args.initial_count = 1;

    uint32_t crc = CalcRecursionHashEnc(&args);

    result =
        oe_call_enclave(EnclaveWrap::Get(enclave_id), "EncRecursion", &args);
    OE_TEST(result == OE_OK);

    printf(
        "%s(EnclaveId=%llu, FlowId=%u, RecursionDepth=%u): "
        "Expect CRC %#x, have CRC %#x, %s\n",
        __FUNCTION__,
        OE_LLU(enclave_id),
        flow_id,
        recursion_depth,
        crc,
        args.crc,
        (crc == args.crc) ? "MATCH" : "MISMATCH");
    OE_TEST(crc == args.crc);
    return crc;
}

// Thread helper to perform recursion tests in parallel across multiple threads.
static void RecursionThread(
    unsigned enclave_id,
    bool rotate_enclaves,
    unsigned flow_id,
    unsigned recursion_depth,
    unsigned loop_count,
    uint32_t expected_crc)
{
    // a barrier would be nice here, though we have no support in gcc yet.
    for (unsigned l = 0; l < loop_count; l++)
    {
        oe_result_t result;
        EncRecursionArg args = {};

        args.enclave_id = enclave_id;
        args.flow_id = flow_id;
        args.recursions_left = recursion_depth;
        args.initial_count = rotate_enclaves ? g_rotating_enclave_ids.size() : 1;
        args.is_rotating_enclave = !!rotate_enclaves;

        result =
            oe_call_enclave(EnclaveWrap::Get(enclave_id), "EncRecursion", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.crc == expected_crc);
    }
}

// Parallel recursion test.
static void TestRecursionParallel(
    std::vector<unsigned> enclave_ids,
    unsigned thread_count,
    unsigned recursion_depth,
    unsigned loop_count)
{
    std::vector<std::thread> threads;
    std::map<unsigned, std::vector<uint32_t>> expected_crcs;

    printf("%s(): Test recursion w/ multiple enclaves {", __FUNCTION__);
    for (unsigned e : enclave_ids)
        printf("%u ", e);
    printf(
        "} with %u threads each, rec-depth %u, loop-count %u\n",
        thread_count,
        recursion_depth,
        loop_count);

    // Precalculate CRCs
    for (unsigned enclave_id : enclave_ids)
    {
        for (unsigned i = 0; i < thread_count; i++)
        {
            EncRecursionArg args = {};
            args.enclave_id = enclave_id;
            args.flow_id = i + 1;
            args.recursions_left = recursion_depth + i;
            args.initial_count = 1;

            expected_crcs[enclave_id].push_back(CalcRecursionHashEnc(&args));
        }
    }

    for (unsigned enclave_id : enclave_ids)
    {
        for (unsigned i = 0; i < thread_count; i++)
        {
            threads.push_back(
                std::thread(
                    RecursionThread,
                    enclave_id,
                    false,
                    i + 1,
                    recursion_depth + i,
                    loop_count,
                    expected_crcs[enclave_id][i]));
        }
    }

    for (auto& t : threads)
    {
        t.join();
    }
}

// Parallel recursion test, across threads
static void TestRecursionCrossEnclave(
    std::vector<unsigned> enclave_ids,
    unsigned thread_count,
    unsigned recursion_depth,
    unsigned loop_count)
{
    std::vector<std::thread> threads;
    std::vector<unsigned> expected_crcs;

    printf("%s(): Test recursion across enclaves {", __FUNCTION__);
    for (unsigned e : enclave_ids)
        printf("%u ", e);
    printf(
        "} with %u threads total, rec-depth %u, loop-count %u\n",
        thread_count,
        recursion_depth,
        loop_count);

    g_rotating_enclave_ids.clear();
    for (unsigned enclave_id : enclave_ids)
        g_rotating_enclave_ids.insert(enclave_id);

    // Precalculate CRCs
    for (unsigned i = 0; i < thread_count; i++)
    {
        EncRecursionArg args = {};
        args.enclave_id = enclave_ids[i % enclave_ids.size()];
        args.flow_id = i + 1;
        args.recursions_left = recursion_depth + i;
        args.initial_count = enclave_ids.size();
        args.is_rotating_enclave = 1;

        expected_crcs.push_back(CalcRecursionHashEnc(&args));
    }

    for (unsigned i = 0; i < thread_count; i++)
    {
        threads.push_back(
            std::thread(
                RecursionThread,
                enclave_ids[i % enclave_ids.size()],
                true,
                i + 1,
                recursion_depth + i,
                loop_count,
                expected_crcs[i]));
    }

    for (auto& t : threads)
    {
        t.join();
    }

    g_rotating_enclave_ids.clear();
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    OE_TEST(InitOCallValues.size() == 0);
    EnclaveWrap enc1(argv[1], flags);
    // verify initial OCall succeeded
    OE_TEST(InitOCallValues.size() == 1);
    OE_TEST(InitOCallValues[0] != NULL);
    OE_TEST(InitOCallValues[0] == enc1.GetBase());
    TestInitOcallResult(enc1.GetId());

    // invalid function tests
    TestInvalidFunctions(enc1.GetId());

    // verify threads execute in parallel
    TestExecutionParallel({enc1.GetId()}, THREAD_COUNT);

    // serial recursion tests.
    OE_TEST(TestRecursion(enc1.GetId(), 1, 33) == 0xb6b66b4d);
    OE_TEST(TestRecursion(enc1.GetId(), 2, 33) == 0x721ea484);
    OE_TEST(TestRecursion(enc1.GetId(), 3, 100) == 0x83fab7f6);

    // Test in a 2nd enclave
    EnclaveWrap enc2(argv[1], flags);
    // verify initial OCall succeeded
    OE_TEST(InitOCallValues.size() == 2);
    OE_TEST(InitOCallValues[1] != NULL);
    OE_TEST(InitOCallValues[1] != InitOCallValues[0]);
    OE_TEST(InitOCallValues[1] == enc2.GetBase());
    TestInitOcallResult(enc2.GetId());

    // verify threads execute in parallel across enclaves
    TestExecutionParallel({enc1.GetId(), enc2.GetId()}, THREAD_COUNT);

    // verify recursion in 2nd enclave by itself
    OE_TEST(TestRecursion(enc2.GetId(), 1, 33) == 0xf3d31c55);

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
