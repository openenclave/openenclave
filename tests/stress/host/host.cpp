// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "stress_u.h"

void do_ecall_in_enclave(
    const char* path,
    uint32_t flags,
    int ecall_count,
    int is_diff_enc)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_stress_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_stress_enclave(): result=%u", result);

    if (is_diff_enc != 0)
        printf("Do ecall in enclave: %d\n", is_diff_enc);
    for (int i = 0; i < ecall_count; i++)
    {
        if ((result = do_ecall(enclave, i)) != OE_OK)
        {
            oe_terminate_enclave(enclave);
            oe_put_err("test(): result=%u", result);
        }
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

void do_ecall_by_count_in_same_env(
    const char* path,
    uint32_t flags,
    int ecall_count,
    int is_diff_enc)
{
    do_ecall_in_enclave(path, flags, ecall_count, is_diff_enc);
}

void do_ecall_by_count_in_diff_env_sequential(
    const char* path,
    uint32_t flags,
    int ecall_count,
    int enclave_count)
{
    for (int i = 1; i < enclave_count + 1; i++)
        do_ecall_in_enclave(path, flags, ecall_count, i);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    // load enclave stress test:
    // realized in create-rapid

    // do ecall stress test:
    int ecall_count;
    int enclave_count;
    int is_diff_enc;

    // 1. do ecall by count in same enclave
    // 1 enclave, 100000 ecalls
    ecall_count = 100000;
    is_diff_enc = 0;
    do_ecall_by_count_in_same_env(argv[1], flags, ecall_count, is_diff_enc);

    // 2. do ecall by count in diff enclaves sequentially
    // 100 enclaves, 10000 ecalls for each enclave, sequential
    ecall_count = 10000;
    enclave_count = 100;
    do_ecall_by_count_in_diff_env_sequential(
        argv[1], flags, ecall_count, enclave_count);

    // to add more do ecall stress tests:
    // 3. do ecall by count in diff enclaves parallelly
    // 4. do ecall by count with multi-threads
    // 5. do ecall by timeout(hour, min, sec)

    // to add: do ocall stress tests, same as above

    // to add: more stress tests
}
