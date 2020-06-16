// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "stress_u.h"

#define ECALL_STRESS_TEST 0
#define OCALL_STRESS_TEST 1
#define ECALL_OCALL_STRESS_TEST 2
// to add: more stress test types

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

    printf("Start to do ecall in enclave: %d\n", enclave_count);
    for (int i = 0; i < ecall_count; i++)
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
        ecall_count);

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

int main(int argc, const char* argv[])
{
    if (argc != 5)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH TEST_TYPE ENCLAVE_COUNT ECALL_COUNT\n",
            argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    // load enclave stress test:
    // realized in create-rapid

    // do ecall / ocall / ecall + ocall stress test:
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
        // to add: TEST_TYPE=2 - do ecall + ocall stress test
        case ECALL_OCALL_STRESS_TEST:
            break;
        // to add: more stress tests
        default:
            break;
    }
}
