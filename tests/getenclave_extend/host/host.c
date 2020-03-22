// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "getenclave_u.h"

#define FLAG_DEBUG_TYPE_SGX_ENC_DBG 0
#define FLAG_DEBUG_TYPE_AUTO_ENC_DBG 1
#define FLAG_SIMULATE_TYPE_SGX_ENC_DBG 2
#define FLAG_SIMULATE_TYPE_AUTO_ENC_DBG 3
#define FLAG_DEBUG_TYPE_SGX_ENC_NONDBG 4
#define FLAG_DEBUG_TYPE_AUTO_ENC_NONDBG 5
#define FLAG_SIMULATE_TYPE_SGX_ENC_NONDBG 6
#define FLAG_SIMULATE_TYPE_AUTO_ENC_NONDBG 7

static oe_enclave_t* _enclave;
static bool _called_test_get_enclave_ocall;

void test_get_enclave_ocall(oe_enclave_t* enclave_param)
{
    OE_TEST(enclave_param == _enclave);
    _called_test_get_enclave_ocall = true;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_result_t expected_result = OE_OK;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH TEST_NUMBER\n", argv[0]);
        return 1;
    }

    uint32_t flags = oe_get_create_flags();
    oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    switch (atoi(argv[2]))
    {
        case FLAG_DEBUG_TYPE_SGX_ENC_DBG:
            flags = OE_ENCLAVE_FLAG_DEBUG;
            type = OE_ENCLAVE_TYPE_SGX;
            break;
        case FLAG_DEBUG_TYPE_AUTO_ENC_DBG:
            flags = OE_ENCLAVE_FLAG_DEBUG;
            type = OE_ENCLAVE_TYPE_AUTO;
            break;
        case FLAG_SIMULATE_TYPE_SGX_ENC_DBG:
            flags = OE_ENCLAVE_FLAG_SIMULATE;
            type = OE_ENCLAVE_TYPE_SGX;
            break;
        case FLAG_SIMULATE_TYPE_AUTO_ENC_DBG:
            flags = OE_ENCLAVE_FLAG_SIMULATE;
            type = OE_ENCLAVE_TYPE_AUTO;
            break;
        case FLAG_DEBUG_TYPE_SGX_ENC_NONDBG:
            flags = OE_ENCLAVE_FLAG_DEBUG;
            type = OE_ENCLAVE_TYPE_SGX;
            expected_result = OE_DEBUG_DOWNGRADE;
            break;
        case FLAG_DEBUG_TYPE_AUTO_ENC_NONDBG:
            flags = OE_ENCLAVE_FLAG_DEBUG;
            type = OE_ENCLAVE_TYPE_AUTO;
            expected_result = OE_DEBUG_DOWNGRADE;
            break;
        case FLAG_SIMULATE_TYPE_SGX_ENC_NONDBG:
            flags = OE_ENCLAVE_FLAG_SIMULATE;
            type = OE_ENCLAVE_TYPE_SGX;
            break;
        case FLAG_SIMULATE_TYPE_AUTO_ENC_NONDBG:
            flags = OE_ENCLAVE_FLAG_SIMULATE;
            type = OE_ENCLAVE_TYPE_AUTO;
            break;
        default:
            break;
    }

    result =
        oe_create_getenclave_enclave(argv[1], type, flags, NULL, 0, &_enclave);

    OE_TEST(result == expected_result);

    if (expected_result != OE_DEBUG_DOWNGRADE)
    {
        oe_result_t return_value;
        result = test_get_enclave_ecall(_enclave, &return_value, _enclave);
        OE_TEST(result == OE_OK);
        OE_TEST(return_value == OE_OK);
        OE_TEST(_called_test_get_enclave_ocall == true);

        oe_terminate_enclave(_enclave);
    }

    printf("=== passed all tests (echo)\n");

    return 0;
}
