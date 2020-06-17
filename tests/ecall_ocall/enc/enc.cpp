// Copyright (c) Open Enclave SDK contributors.
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
#include "ecall_ocall_t.h"
#include "helpers.h"

unsigned g_enclave_id = ~0u;

static tls_wrapper g_per_thread_flow_id;

// class to verify OCalls in static Initializers
class static_init_ocaller
{
  public:
    static_init_ocaller() : m_result(OE_FAILURE)
    {
        m_result =
            init_ocall_handler(const_cast<void*>(__oe_get_enclave_base()));
        OE_TEST(m_result == OE_OK);
    }

    oe_result_t get_ocall_result() const
    {
        return m_result;
    }

  private:
    oe_result_t m_result;
};

static static_init_ocaller g_static_init_ocaller;

// obtain static init ocall result
oe_result_t enc_get_init_ocall_result()
{
    return g_static_init_ocaller.get_ocall_result();
}

// Set custom enclave ID for later tracking
oe_result_t enc_set_enclave_id(unsigned id, const void** base_addr)
{
    oe_result_t result = OE_OK;

    if (g_enclave_id == ~0u)
    {
        g_enclave_id = id;
        *base_addr = __oe_get_enclave_base();
    }
    else
    {
        result = OE_INVALID_PARAMETER;
    }
    return result;
}

// Parallel execution test. Using a (trivialized) barrier in the host,
// spin-wait until all expected threads reach it, w/o performing an ocall.
oe_result_t enc_parallel_execution(
    unsigned flow_id,
    void* _counter,
    void* _release)
{
    oe_result_t result = OE_OK;
    std::atomic<unsigned>* counter =
        reinterpret_cast<std::atomic<unsigned>*>(_counter);
    std::atomic<unsigned>* release =
        reinterpret_cast<std::atomic<unsigned>*>(_release);

    unsigned old_flow_id = g_per_thread_flow_id.get_u();
    if (0 == old_flow_id)
    {
        g_per_thread_flow_id.set(flow_id);

        ++(*counter);

        // Wait for the signal from host before continuing.
        // (wait until release becomes non-zero)
        while (0 == release->load(std::memory_order_acquire))
            ;

        old_flow_id = g_per_thread_flow_id.get_u();
        if (old_flow_id != flow_id)
        {
            printf(
                "%s(): Stopping flow=%u, though overwritten with %u\n",
                __FUNCTION__,
                flow_id,
                old_flow_id);
            result = OE_UNEXPECTED;
        }
        g_per_thread_flow_id.set(0u);
    }
    else
    {
        printf(
            "%s(): Starting flow=%u, though thread already has %u\n",
            __FUNCTION__,
            flow_id,
            old_flow_id);
        result = OE_INVALID_PARAMETER;
    }

    return result;
}

uint32_t g_factor = 0;

uint32_t enc_cross_enclave_call(
    uint32_t enclave_id,
    uint32_t value,
    uint32_t total)
{
    oe_result_t result =
        host_cross_enclave_call(&total, enclave_id + 1, value + 1, total);
    OE_TEST(OE_OK == result);

    // augment the total with the add_value.
    uint32_t add_value = value * g_factor;
    total += add_value;
    printf(
        "enclave %u: factor=%u, add_value=%u, total=%u\n",
        enclave_id,
        g_factor,
        add_value,
        total);
    return total;
}

void enc_set_factor(uint32_t factor)
{
    g_factor = factor;
}

void enc_make_ocall(int n)
{
    host_ocall_pointer(&n);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages */
    16,   /* NumStackPages */
    5);   /* NumTCS */
