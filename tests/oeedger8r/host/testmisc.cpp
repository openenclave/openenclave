// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <algorithm>
#include "all_u.h"

void run_misc_tests(oe_enclave_t* enclave)
{
    int8_t* ptr = NULL;

    // Get pointer from enclave.
    OE_TEST(get_enclave_mem_ptr(enclave, &ptr) == OE_OK);
    OE_TEST(ptr != NULL);

    int8_t arr[25];

    // Pass invalid first pointer.
    OE_TEST(test_invalid_ptr(enclave, ptr, arr) == OE_INVALID_PARAMETER);

    // Pass invalid second pointer.
    OE_TEST(test_invalid_ptr(enclave, arr, ptr) == OE_INVALID_PARAMETER);

    printf("=== misc tests passed\n");
}
