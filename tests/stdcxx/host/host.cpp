// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

#if 0
#define ECHO
#endif

uint64_t prev;

void TestStdcxx(oe_enclave_t* enclave)
{
    oe_result_t result;
    TestArgs args;

    printf("=== %s() \n", __FUNCTION__);
    result = oe_call_enclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.ret == 0);
    OE_TEST(args.caught);
    OE_TEST(args.dynamic_cast_works);
    OE_TEST(args.num_constructions == 6);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 3)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH OE_OK/OE_ENCLAVE_ABORTING\n",
            argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, NULL, 0, &enclave);

    if (strcmp(argv[2], oe_result_str(OE_ENCLAVE_ABORTING)) == 0)
    {
        if (strcmp(oe_result_str(result), argv[2]) == 0)
        {
            printf(
                "=== Passed: enclave not created, enclave status: (%s)\n",
                oe_result_str(result));
            goto done;
        }
        oe_put_err("oe_create_enclave(): result=%u", result);
    }
    else if (strcmp(argv[2], oe_result_str(OE_OK)) == 0)
    {
        if (strcmp(oe_result_str(result), argv[2]) == 0)
        {
            TestStdcxx(enclave);
            printf("=== passed all tests (%s)\n", argv[0]);
            goto done;
        }
        oe_put_err("oe_create_enclave(): result=%u", result);
    }
    else
        oe_put_err("Invalid argument: %s", argv[2]);

done:
    if (enclave)
    {
        if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        {
            oe_put_err("oe_terminate_enclave(): result=%u", result);
        }
    }

    return 0;
}
