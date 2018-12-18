// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "enclaveparam_u.h"

oe_enclave_t* enclave_1;
oe_enclave_t* enclave_2;
oe_enclave_t* enclave_3;

size_t called_callback_1;
size_t called_callback_2;
size_t called_callback_3;

void callback_1(oe_enclave_t* enclave)
{
    oe_result_t result;

    OE_TEST(enclave == enclave_1);

    /* Call into enclave b, which calls callback_2 */
    result = test_ocall_enclave_param(enclave_2, "callback_2");
    OE_TEST(result == OE_OK);

    called_callback_1++;
}

void callback_2(oe_enclave_t* enclave)
{
    oe_result_t result;

    OE_TEST(enclave == enclave_2);

    /* Call into enclave c, which calls callback_3 */
    result = test_ocall_enclave_param(enclave_3, "callback_3");
    OE_TEST(result == OE_OK);

    called_callback_2++;
}

void callback_3(oe_enclave_t* enclave)
{
    OE_TEST(enclave == enclave_3);
    called_callback_3++;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_enclaveparam_enclave(
        argv[1], type, flags, NULL, 0, &enclave_1);
    OE_TEST(result == OE_OK);

    result = oe_create_enclaveparam_enclave(
        argv[1], type, flags, NULL, 0, &enclave_2);
    OE_TEST(result == OE_OK);

    result = oe_create_enclaveparam_enclave(
        argv[1], type, flags, NULL, 0, &enclave_3);
    OE_TEST(result == OE_OK);

    /* Call into enclave a, which calls callback_1 */
    result = test_ocall_enclave_param(enclave_1, "callback_1");
    OE_TEST(result == OE_OK);

    oe_terminate_enclave(enclave_1);
    oe_terminate_enclave(enclave_2);
    oe_terminate_enclave(enclave_3);

    OE_TEST(called_callback_1 == 1);
    OE_TEST(called_callback_2 == 1);
    OE_TEST(called_callback_3 == 1);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
