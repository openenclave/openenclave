// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/types.h>
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
                 enclave_path,
                 OE_ENCLAVE_TYPE_SGX,
                 flags,
                 NULL,
                 0,
                 NULL,
                 0,
                 &enclave)) != OE_OK)
        {
            oe_put_err("oe_create_enclave(): result=%u", result);
            throw std::runtime_error("oe_create_enclave() failed");
        }
        m_id = static_cast<unsigned>(m_enclaves.size());

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

    static oe_enclave_t* Get(uint64_t Id)
    {
        return m_enclaves[Id];
    }

    static size_t Count()
    {
        return m_enclaves.size();
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
        if (get_current_logging_level() >= OE_LOG_LEVEL_INFO)
        {
            static unsigned old_val;
            if (counter != old_val)
            {
                printf(
                    "%s(): Looking for counter=%u, have %u.\n",
                    __FUNCTION__,
                    (unsigned)enclave_ids.size() * thread_count,
                    counter);
                old_val = counter;
            }
        }
    }
    // all threads arrived and spin on the release
    release = 1;

    for (auto& t : threads)
    {
        t.join();
    }
}

OE_OCALL void CrossEnclaveCall(CrossEnclaveCallArg* arg)
{
    if (arg->enclave_id < EnclaveWrap::Count())
    {
        // Forward the call to the next enclave.
        OE_TEST(
            oe_call_enclave(
                EnclaveWrap::Get(arg->enclave_id),
                "EncCrossEnclaveCall",
                arg) == OE_OK);
    }
    else
    {
        // All enclaves are currently blocked on OCALLs
        // in the main thread (this thread).
        // Ecalls from current thread should fail.
        // But Ecalls from another thread should succeed.
        for (size_t i = 0; i < EnclaveWrap::Count(); ++i)
        {
            OE_TEST(
                oe_call_enclave(
                    EnclaveWrap::Get(i), "EncSetFactor", (void*)(i + 1)) ==
                OE_REENTRANT_ECALL);

            std::thread t([i]() {
                OE_TEST(
                    oe_call_enclave(
                        EnclaveWrap::Get(i), "EncSetFactor", (void*)(i + 1)) ==
                    OE_OK);
            });
            t.join();
        }
    }
}

// Test scenarios where ocall from one enclave calls into another
// enclave. Each enclave computes its result by multiplying
// the input value by a factor. Each enclave calls the next enclave
// (via host) with incremented input value and adds its own result to
// the result computed by the next enclave.
// All the factors are initially zero.
// When all the enclaves are executing ocalls, separate threads are
// launched that set the factors in each of the enclaves.
// This tests the scenario that when one enclave thread is blocked in
// an ocall, other enclave threads can process ecalls.
static void TestCrossEnclaveCalls()
{
    CrossEnclaveCallArg arg = {
        0, // start with first enclave
        8, // input value
        0, // output value.
    };

    size_t expected_output = 0;
    for (size_t i = 0; i < EnclaveWrap::Count(); ++i)
    {
        expected_output += (arg.input + i) * (i + 1);
    }

    OE_TEST(
        oe_call_enclave(EnclaveWrap::Get(0), "EncCrossEnclaveCall", &arg) ==
        OE_OK);
    printf("arg.output=%u, expected_output=%lu\n", arg.output, expected_output);
    OE_TEST(arg.output == expected_output);

    printf("=== TestCrossEnclaveCalls passed\n");
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

    // Verify enclaves calling each other via the host.
    // Create 5 enclaves.
    EnclaveWrap enc3(argv[1], flags);
    EnclaveWrap enc4(argv[1], flags);
    EnclaveWrap enc5(argv[1], flags);
    TestCrossEnclaveCalls();

    return 0;
}
