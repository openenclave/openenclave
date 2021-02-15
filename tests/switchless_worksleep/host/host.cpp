// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <inttypes.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>
#include "../../../host/hostthread.h"
#include "../../../host/strings.h"
#include "switchless_worksleep_u.h"
using namespace std;

// global counters to increment in ocalls
uint32_t ocall1_counter = 0;
uint32_t ocall2_counter = 0;

/**
 * ocall1 - increment counter and return
 */
void host_ocall1_switchless(void)
{
    ocall1_counter++;
}

/**
 * ocall2 - increment counter and return
 */
void host_ocall2_switchless(void)
{
    ocall2_counter++;
}

/**
 * thread worker method
 * call ecall1 and ecall2 1000 times
 * count failures
 * sleep 1 second and repeat the above
 */
void* thread_func(void* arg)
{
    uint32_t fails = 0, i = 0;
    oe_result_t ret = OE_OK;
    oe_enclave_t* enclave = (oe_enclave_t*)arg;

    // run ecalls
    for (i = 0; i < 1000; i++)
    {
        ret = enc_ecall1_switchless(enclave);
        if (ret != OE_OK)
        {
            fails++;
        }
        ret = enc_ecall2_switchless(enclave);
        if (ret != OE_OK)
        {
            fails++;
        }
    }
    OE_TEST(fails == 0);

    // sleep 1 second
    this_thread::sleep_for(std::chrono::milliseconds(1000));

    // run ecalls again
    for (i = 0; i < 1000; i++)
    {
        ret = enc_ecall1_switchless(enclave);
        if (ret != OE_OK)
        {
            fails++;
        }
        ret = enc_ecall2_switchless(enclave);
        if (ret != OE_OK)
        {
            fails++;
        }
    }
    OE_TEST(fails == 0);
    return NULL;
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("Run Sleep-Wake test.\n");

    // check number of cores, need at least 4
    uint32_t cores = thread::hardware_concurrency();
    // if not enough cores, exit, but don't fail the test
    if (cores < 4)
    {
        printf(
            "Test System has only (%d) cores, can't run test, exit\n", cores);
        return 0;
    }
    printf("Test System runs (%d) CPUs\n", cores);

    uint32_t workers = cores / 4;

    printf(
        "Creating enclave with SwitchlessCalls - (%d) trusted worker threads "
        "and "
        "(%d) untrusted worker threads\n",
        workers,
        workers);

    const uint32_t flags = oe_get_create_flags();

    oe_enclave_setting_context_switchless_t switchless_setting = {workers,
                                                                  workers};
    oe_enclave_setting_t setting;
    setting.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS;
    setting.u.context_switchless_setting = &switchless_setting;

    if ((result = oe_create_switchless_worksleep_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, &setting, 1, &enclave)) !=
        OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    vector<oe_thread_t> app_threads;
    uint32_t app_workers = cores - workers - workers;
    printf("Launching (%d) application threads\n", app_workers);

    uint32_t i;
    oe_thread_t thread;
    int ret = 0;
    for (i = 0; i < app_workers; i++)
    {
        if ((ret = oe_thread_create(&thread, thread_func, enclave)))
        {
            oe_put_err("thread_create(host): ret=%u", ret);
        }
        app_threads.push_back(thread);
    }

    for (i = 0; i < app_threads.size(); i++)
    {
        oe_thread_join(app_threads[i]);
    }

    // remove threads from vector
    app_threads.clear();

    // run threads again
    printf("Launching (%d) application threads again\n", app_workers);
    for (i = 0; i < app_workers; i++)
    {
        if ((ret = oe_thread_create(&thread, thread_func, enclave)))
        {
            oe_put_err("thread_create(host): ret=%u", ret);
        }
        app_threads.push_back(thread);
    }

    for (i = 0; i < app_threads.size(); i++)
    {
        oe_thread_join(app_threads[i]);
    }

    // remove threads from vector
    app_threads.clear();

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed all tests (switchless_worksleep)\n");

    return 0;
}
