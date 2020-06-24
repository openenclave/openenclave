
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
    OE_TEST(security_ecall_test1(enclave, location) == OE_INVALID_PARAMETER);

    // Pass location back to enclave via struct deepcopy.
    SecurityS s = {location};
    OE_TEST(security_ecall_test2(enclave, &s) == OE_INVALID_PARAMETER);

    // Pass location back to enclave via in/out parameter.
    OE_TEST(security_ecall_test3(enclave, location) == OE_INVALID_PARAMETER);

    // Pass location back to enclave via struct deepcopy in/out parameter.
    OE_TEST(security_ecall_test4(enclave, &s) == OE_INVALID_PARAMETER);

    printf("=== expect four OE_INVALID_PARAMETER errors above ======\n");
    printf("=== test_security passed\n");
}
