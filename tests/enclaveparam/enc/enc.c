// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>

OE_ECALL void test_get_host_enclave(void* args)
{
    const char* func = (const char*)args;
    OE_TEST(func != NULL);

    oe_result_t result = oe_call_host(func, args);
    OE_TEST(result == OE_OK);
}
