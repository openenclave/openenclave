// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "libc_u.h"

void Test(oe_enclave_t* enclave)
{
    int rval = 1;
    oe_result_t result = test(enclave, &rval);
    OE_TEST(result == OE_OK);

    if (rval == 0)
    {
        printf("=== passed\n");
    }
    else
    {
        printf("*** failed\n");
        abort();
    }
}

void ocall_exit(uint64_t arg)
{
    exit(static_cast<int>(arg));
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    oe_result_t result;
    const uint32_t flags = oe_get_create_flags();

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

    // Create the enclave:
    if ((result = oe_create_libc_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_libc_enclave(): result=%u", result);

    Test(enclave);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
