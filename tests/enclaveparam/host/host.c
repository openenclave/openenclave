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

oe_enclave_t* enclave_1;
oe_enclave_t* enclave_2;
oe_enclave_t* enclave_3;

size_t called_callback_1;
size_t called_callback_2;
size_t called_callback_3;

OE_OCALL void callback_1(void* args, oe_enclave_t* enclave)
{
    oe_result_t result;

    OE_TEST(enclave == enclave_1);

    /* Call into enclave b, which calls callback_2 */
    result =
        oe_call_enclave(enclave_2, "test_ocall_enclave_param", "callback_2");
    OE_TEST(result == OE_OK);

    called_callback_1++;
}

OE_OCALL void callback_2(void* args, oe_enclave_t* enclave)
{
    oe_result_t result;

    OE_TEST(enclave == enclave_2);

    /* Call into enclave c, which calls callback_3 */
    result =
        oe_call_enclave(enclave_3, "test_ocall_enclave_param", "callback_3");
    OE_TEST(result == OE_OK);

    called_callback_2++;
}

OE_OCALL void callback_3(void* args, oe_enclave_t* enclave)
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

    printf("argv[1]=%s\n", argv[1]);

    result = oe_create_enclave(argv[1], type, flags, NULL, 0, &enclave_1);
    OE_TEST(result == OE_OK);

    result = oe_create_enclave(argv[1], type, flags, NULL, 0, &enclave_2);
    OE_TEST(result == OE_OK);

    result = oe_create_enclave(argv[1], type, flags, NULL, 0, &enclave_3);
    OE_TEST(result == OE_OK);

    /* Call into enclave a, which calls callback_1 */
    result =
        oe_call_enclave(enclave_1, "test_ocall_enclave_param", "callback_1");
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
