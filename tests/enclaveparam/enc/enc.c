// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>

OE_ECALL void test_ocall_enclave_param(void* args)
{
    const char* func = (const char*)args;
    OE_TEST(func != NULL);

    oe_result_t result = oe_call_host(func, args);
    OE_TEST(result == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    4);   /* TCSCount */
