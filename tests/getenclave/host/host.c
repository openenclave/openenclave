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

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

    result =
        oe_create_getenclave_enclave(argv[1], type, flags, NULL, 0, &_enclave);
    OE_TEST(result == OE_OK);

    oe_result_t return_value;
    result = test_get_enclave_ecall(_enclave, &return_value, _enclave);
    OE_TEST(result == OE_OK);
    OE_TEST(return_value == OE_OK);
    OE_TEST(_called_test_get_enclave_ocall == true);

    oe_terminate_enclave(_enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
