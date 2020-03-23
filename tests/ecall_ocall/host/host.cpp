// Copyright (c) Open Enclave SDK contributors.
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
#include "ecall_ocall_u.h"

#define THREAD_COUNT 5 // must not exceed what is configured in sign.conf

// Slightly specialized wrapper around an oe_enclave_t object to allow
// scope-based lifetime mgmt. Also a bit of identifying glue (which relies on
// custom code in the enclave).
class enclave_wrap
{
  public:
    enclave_wrap(const char* enclave_path, uint32_t flags)
    {
        oe_enclave_t* enclave = NULL;
        oe_result_t result = oe_create_ecall_ocall_enclave(
            enclave_path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (result != OE_OK)
        {
            oe_put_err("oe_create_ecall_ocall_enclave(): result=%u", result);
            throw std::runtime_error("oe_create_ecall_ocall_enclave() failed");
        }
        m_id = static_cast<unsigned>(s_enclaves.size());

        oe_result_t ret_result = OE_FAILURE;
        const void* base_addr = NULL;
        if ((result = enc_set_enclave_id(
                 enclave, &ret_result, m_id, &base_addr)) != OE_OK)
        {
            oe_put_err("enc_set_enclave_id): result=%u", result);
            throw std::runtime_error("enc_set_enclave_id failed");
        }
        if (ret_result != OE_OK)
        {
            oe_put_err("enc_set_enclave_id(): ret_result=%u", ret_result);
            throw std::runtime_error("enc_set_enclave_id() failed");
        }

        m_enclave_base = base_addr;
        s_enclaves.push_back(enclave);
    }

    ~enclave_wrap()
    {
        oe_result_t result;
        if ((result = oe_terminate_enclave(get())) != OE_OK)
        {
            oe_put_err("oe_terminate_enclave(): result=%u", result);
        }
        // simplified cleanup to keep identifiers stable
        s_enclaves[m_id] = NULL;
    }

    unsigned get_id() const
    {
        return m_id;
    }
    const void* get_base() const
    {
        return m_enclave_base;
    }
    oe_enclave_t* get() const
    {
        return s_enclaves[m_id];
    }

    static oe_enclave_t* get(uint64_t id)
    {
        return s_enclaves[id];
    }

    static size_t count()
    {
        return s_enclaves.size();
    }

  private:
    unsigned m_id;
    const void* m_enclave_base;
    static std::vector<oe_enclave_t*> s_enclaves;
};
std::vector<oe_enclave_t*> enclave_wrap::s_enclaves;

static std::vector<void*> g_init_ocall_values;

// OCall handler for initial ocall testing - track argument for later
// verification
void init_ocall_handler(void* arg)
{
    g_init_ocall_values.push_back(arg);
}

// Initial OCall test helper - Verify that the ocall happened (by asking the
// enclave), and obtain the result of it.
void test_init_ocall_result(unsigned enclave_id)
{
    oe_result_t ret_result = OE_FAILURE;
    oe_result_t result =
        enc_get_init_ocall_result(enclave_wrap::get(enclave_id), &ret_result);
    OE_TEST(result == OE_OK);
    OE_TEST(ret_result == OE_OK);
}

// Helper function for parallel test
static void parallel_thread(
    unsigned enclave_id,
    unsigned flow_id,
    std::atomic<unsigned>* counter,
    std::atomic<unsigned>* release)
{
    oe_result_t ret_result = OE_FAILURE;

    OE_TRACE_INFO(
        "%s(Enclave=%u, Flow=%u) started\n", __FUNCTION__, enclave_id, flow_id);
    oe_result_t result = enc_parallel_execution(
        enclave_wrap::get(enclave_id), &ret_result, flow_id, counter, release);
    OE_TRACE_INFO(
        "%s(Enclave=%u, Flow=%u) done.\n", __FUNCTION__, enclave_id, flow_id);
    OE_TEST(result == OE_OK);
    OE_TEST(ret_result == OE_OK);
}

// Parallel execution test - verify parallel threads are actually executed
static void test_execution_parallel(
    std::vector<unsigned> enclave_ids,
    unsigned thread_count)
{
    std::vector<std::thread> threads;
    std::atomic<unsigned> counter(0);
    std::atomic<unsigned> release(0);

    printf("%s(): Test parallel execution across enclaves {", __FUNCTION__);
    for (unsigned e : enclave_ids)
    {
        printf("%u ", e);
    }
    printf("} with %u threads each\n", thread_count);

    for (unsigned enclave_id : enclave_ids)
    {
        for (unsigned i = 0; i < thread_count; i++)
        {
            threads.push_back(std::thread(
                parallel_thread, enclave_id, i + 1, &counter, &release));
        }
    }

    // wait for all enclave-threads to have incremented the counter
    unsigned count = counter.load(std::memory_order_acquire);
    unsigned old_val = ~count;
    while (count < enclave_ids.size() * thread_count)
    {
        if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
        {
            if (count != old_val)
            {
                printf(
                    "%s(): Looking for counter=%u, have %u.\n",
                    __FUNCTION__,
                    (unsigned)enclave_ids.size() * thread_count,
                    count);
                old_val = count;
            }
        }
        count = counter.load(std::memory_order_acquire);
    }
    // all threads arrived and spin on the release
    release.store(1, std::memory_order_release);

    for (auto& t : threads)
    {
        t.join();
    }
}

uint32_t host_cross_enclave_call(
    uint32_t enclave_id,
    uint32_t value,
    uint32_t total)
{
    if (enclave_id < enclave_wrap::count())
    {
        // Forward the call to the next enclave.
        OE_TEST(
            enc_cross_enclave_call(
                enclave_wrap::get(enclave_id),
                &total,
                enclave_id,
                value,
                total) == OE_OK);
    }
    else
    {
        // All enclaves are currently blocked on OCALLs
        // in the main thread (this thread).
        // Ecalls from current thread should fail.
        // But Ecalls from another thread should succeed.
        for (uint32_t i = 0; i < enclave_wrap::count(); ++i)
        {
            OE_TEST(
                enc_set_factor(enclave_wrap::get(i), i + 1) ==
                OE_REENTRANT_ECALL);

            std::thread t([i]() {
                OE_TEST(enc_set_factor(enclave_wrap::get(i), i + 1) == OE_OK);
            });
            t.join();
        }
    }
    return total;
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
static void test_cross_enclave_calls()
{
    static const uint32_t SEED = 8;

    size_t expected_total = 0;
    for (size_t i = 0; i < enclave_wrap::count(); ++i)
    {
        expected_total += (SEED + i) * (i + 1);
    }

    uint32_t total = 0;
    oe_result_t result =
        enc_cross_enclave_call(enclave_wrap::get(0), &total, 0, SEED, 0);
    OE_TEST(OE_OK == result);

    printf("total=%u, expected_total=%zu\n", total, expected_total);
    OE_TEST(total == expected_total);

    printf("=== test_cross_enclave_calls passed\n");
}

// n is a pointer so that it will lie in the current ecall_context's ocall
// buffer. If all enclaves in the same thread use the same ocall buffer, then
// the value of n will get overwritten. If the ocall-buffers are not shared
// by the enclaves even though they are being used in the same thread,
// the value of n as seen by each ocall will be preserved.
void host_ocall_pointer(int* n)
{
    int starting_value = *n;
    printf("input buffer = 0x%p\n", n);

    if (*n > 0)
    {
        // Trigger an ocall in the next enclave. If the next enclave's
        // ocall uses the same ocall buffer, the value of n will be
        // overwritten.
        OE_TEST(
            enc_make_ocall(enclave_wrap::get((uint64_t)*n - 1), *n - 1) ==
            OE_OK);
    }

    // Assert that the value has been preserved.
    OE_TEST(*n == starting_value);
    printf("enclave %d ocall preserved value\n", *n);
}

static void test_ocall_buffers()
{
    // Start zig-zag ocalls with the 5th enclave.
    OE_TEST(enc_make_ocall(enclave_wrap::get(4), 4) == OE_OK);
    printf("=== test_ocall_buffers passed\n");
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    OE_TEST(g_init_ocall_values.size() == 0);
    enclave_wrap enc1(argv[1], flags);
    // verify initial OCall succeeded
    OE_TEST(g_init_ocall_values.size() == 1);
    OE_TEST(g_init_ocall_values[0] != NULL);
    OE_TEST(g_init_ocall_values[0] == enc1.get_base());
    test_init_ocall_result(enc1.get_id());

    // verify threads execute in parallel
    test_execution_parallel({enc1.get_id()}, THREAD_COUNT);

    // Test in a 2nd enclave
    enclave_wrap enc2(argv[1], flags);
    // verify initial OCall succeeded
    OE_TEST(g_init_ocall_values.size() == 2);
    OE_TEST(g_init_ocall_values[1] != NULL);
    OE_TEST(g_init_ocall_values[1] != g_init_ocall_values[0]);
    OE_TEST(g_init_ocall_values[1] == enc2.get_base());
    test_init_ocall_result(enc2.get_id());

    // verify threads execute in parallel across enclaves
    test_execution_parallel({enc1.get_id(), enc2.get_id()}, THREAD_COUNT);

    // Verify enclaves calling each other via the host.
    // Create 5 enclaves.
    enclave_wrap enc3(argv[1], flags);
    enclave_wrap enc4(argv[1], flags);
    enclave_wrap enc5(argv[1], flags);
    test_cross_enclave_calls();
    test_ocall_buffers();

    return 0;
}
