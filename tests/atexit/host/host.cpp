// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "atexit_u.h"

#define OCALL_WITH_INCREASE_SINGLE 0
#define OCALL_WITH_INCREASE_MULTIPLE 1
#define OCALL_WITH_AN_ECALL 2

oe_enclave_t* enclave = NULL;
int global_var = 0;

void global_variable_increase_ocall(void)
{
    global_var++;
}

void with_an_ecall_ocall(void)
{
    global_var += 3;
    uint32_t magic = 2;
    oe_result_t result = get_magic_ecall(enclave, &magic);
    // should fail since reentrant ecalls not allowed
    OE_TEST(result == OE_REENTRANT_ECALL);
    OE_TEST(2 == magic);
    global_var += 2;
    return;
}

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TEST_NUMBER\n", argv[0]);
        exit(1);
    }

    int expected_value = -1;
    const uint32_t flags = oe_get_create_flags();

    oe_result_t result = oe_create_atexit_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    switch (atoi(argv[2]))
    {
        case OCALL_WITH_INCREASE_SINGLE:
            expected_value = 1;
            result = atexit_1_call_ecall(enclave);
            break;
        case OCALL_WITH_INCREASE_MULTIPLE:
            expected_value = 32;
            result = atexit_32_call_ecall(enclave);
            break;
        case OCALL_WITH_AN_ECALL:
            expected_value = 5;
            result = atexit_with_ecall_ecall(enclave);
            break;
        default:
            break;
    }
    // value should not change when enclave is valid
    OE_TEST(global_var == 0);

    OE_TEST(result == OE_OK);
    // Clean up the enclave
    if (enclave)
        oe_terminate_enclave(enclave);

    OE_TEST(global_var == expected_value);

    return 0;
}
