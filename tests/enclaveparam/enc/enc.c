// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "enclaveparam_t.h"

void test_ocall_enclave_param(char* func)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    oe_enclave_t* enclave = oe_get_enclave();

    OE_TEST(func != NULL);

    if (strcmp(func, "callback_1") == 0)
    {
        result = callback_1(enclave);
    }
    else if (strcmp(func, "callback_2") == 0)
    {
        result = callback_2(enclave);
    }
    else if (strcmp(func, "callback_3") == 0)
    {
        result = callback_3(enclave);
    }

    OE_TEST(result == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128, /* HeapPageCount */
    64, /* StackPageCount */
    4);   /* TCSCount */
