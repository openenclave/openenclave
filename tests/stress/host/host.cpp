// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <malloc.h>
#include <thread>
#include <vector>
#include "stress_u.h"

#define ECALL_STRESS_TEST 0
#define OCALL_STRESS_TEST 1
#define MEMORY_MANAGEMENT_STRESS_TEST 2
#define MULTITHREAD_STRESS_TEST 3

void do_ecall_in_enclave(
    const char* path,
    uint32_t flags,
    int enclave_count,
    int ecall_count)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_stress_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_stress_enclave(): result=%u", result);

    int i;
    printf("Start to do ecall in enclave: %d\n", enclave_count);
    for (i = 0; i < ecall_count; i++)
    {
        if ((result = do_ecall(enclave, i)) != OE_OK)
        {
            oe_terminate_enclave(enclave);
            oe_put_err("test(): result=%u", result);
        }
    }
    printf(
        "Finish doing ecall in enclave: %d, total %d ecalls\n",
        enclave_count,
        i);

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

void do_ecall_by_count_in_env_sequential(
    const char* path,
    uint32_t flags,
    int enclave_count,
    int ecall_count)
{
    for (int i = 1; i < enclave_count + 1; i++)
        do_ecall_in_enclave(path, flags, i, ecall_count);
}

void memory_management(
    const char* path,
    uint32_t flags,
    int memory_count,
    int memory_size)
{
    oe_result_t result;
    oe_result_t return_value;
    oe_enclave_t* enclave = NULL;

    result = oe_create_stress_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_stress_enclave(): result=%u", result);

    int i = 0;
    printf("Start to do malloc in enclave: \n");
    for (i = 0; i < memory_count; i++)
    {
        result = do_malloc(enclave, &return_value, memory_size);
        OE_TEST(result == OE_OK);
    }
    printf("finish doing malloc in enclave: %d\n", i);

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

void create_enclave(
    const char* path,
    uint32_t flags,
    int thread_number,
    int enclave_count)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    for (int i = 0; i < enclave_count; i++) 
    {
        printf("thread %d, enclave %d\n", thread_number, i);
        result = oe_create_stress_enclave(
            path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
        if (result != OE_OK)
            oe_put_err("oe_create_stress_enclave() - %u: result=%u", i, result);

        result = oe_terminate_enclave(enclave);
        if (result != OE_OK)
            oe_put_err("oe_terminate_enclave() - %u: result=%u", i, result);
    }
}

void multi_thread(
    const char* path,
    uint32_t flags,
    int thread_count,
    int enclave_count)
{
    std::vector<std::thread> threads;

    for (int i = 0; i < thread_count; i++)
    {
        threads.emplace_back(
            std::thread(create_enclave, path, flags, i, enclave_count));
    }

    for (auto& thread : threads)
        thread.join();
}

int main(int argc, const char* argv[])
{
    if ((argc != 5) && (argc != 6))
    {
        fprintf(
            stderr,
            "Usage 1: %s ENCLAVE_PATH ${ECALL_STRESS_TEST} ENCLAVE_COUNT DO_ECALL_COUNT\n",
            argv[0]);
        fprintf(
            stderr,
            "Usage 2: %s ENCLAVE_PATH ${MEMORY_MANAGEMENT_STRESS_TEST} DO_MEMORY_COUNT MEMORY_SIZE\n",
            argv[0]);
        fprintf(
            stderr,
            "Usage 3: %s ENCLAVE_PATH ${MULTITHREAD_STRESS_TEST} THREAD_COUNT ENCLAVE_COUNT\n",
            argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    // load enclave stress test:
    // realized in tests/create-rapid/

    // do ecall / ocall / memory management / multi-thread stress test:
    switch (atoi(argv[2]))
    {
        // TEST_TYPE=0 - do ecall stress test
        // 1. do ecall by count in env sequentially
        case ECALL_STRESS_TEST:
            do_ecall_by_count_in_env_sequential(
                argv[1], flags, atoi(argv[3]), atoi(argv[4]));
            // to add more do ecall stress tests:
            // 2. do ecall by count in env parallelly
            // 3. do ecall by count with multi-threads
            // 4. do ecall by timeout(hour, min, sec)
            break;
        // to add: TEST_TYPE=1 - do ocall stress test
        case OCALL_STRESS_TEST:
            break;
        // TEST_TYPE=2 - do memory management stress test
        case MEMORY_MANAGEMENT_STRESS_TEST:
            memory_management(
                argv[1], flags, atoi(argv[3]), atoi(argv[4]));
            break;
        // TEST_TYPE=3 - do multi-thread stress test
        case MULTITHREAD_STRESS_TEST:
            multi_thread(
                argv[1], flags, atoi(argv[3]), atoi(argv[4]));
            break;
        // to add: more stress test scene
        default:
            break;
    }
}
