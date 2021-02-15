
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "all_u.h"

void test_security(oe_enclave_t* enclave)
{
    // Get secret memory location from enclave.
    int* location = NULL;
    OE_TEST(security_get_secret_ptr(enclave, &location) == OE_OK);
    OE_TEST(location != NULL);

    // Pass location back to enclave.
    OE_TEST(security_ecall_test1(enclave, location) == OE_OK);

    int indata[4] = {512, 1024, 768, 2048};
    int ret_value;
    OE_TEST(security_ecall_test2(enclave, &ret_value, indata) == OE_OK);
    OE_TEST(ret_value == 0);
    OE_TEST(indata[0] == 512);
    OE_TEST(indata[1] == 1024);
    OE_TEST(indata[2] == 768);
    OE_TEST(indata[3] == 2048);

    printf("=== test_security passed\n");
}
