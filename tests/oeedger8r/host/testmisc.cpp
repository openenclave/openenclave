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

    // In calls below, the enclave memory pointer is passed in
    // as input array. With previous marshaling scheme, the pointer
    // is passed all the way to enclave which returns OE_INVALID_PARAMETER.
    // With the new marshaling scheme, the array is copied into a flat buffer
    // in the host itself, and the buffer is passed in to the enclave and
    // the call works fine. Note: It is OK to read enclave memory; the value
    // read will be a fixed pattern/constant.

    // Pass invalid first pointer.
    OE_TEST(test_invalid_ptr(enclave, ptr, arr) == OE_OK);

    // Pass invalid second pointer.
    OE_TEST(test_invalid_ptr(enclave, arr, ptr) == OE_OK);

    printf("=== misc tests passed\n");
}
