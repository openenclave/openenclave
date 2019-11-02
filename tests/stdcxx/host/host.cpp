// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "stdcxx_u.h"

#if 0
#define ECHO
#endif

#define SKIP_RETURN_CODE 2

void test_stdcxx(oe_enclave_t* enclave)
{
    int ret = -1;
    bool caught = false;
    bool dynamic_cast_works = false;
    size_t num_constructions = 0;
    oe_result_t result = enc_test(
        enclave, &ret, &caught, &dynamic_cast_works, &num_constructions);
    OE_TEST(result == OE_OK);
    OE_TEST(ret == 0);
    OE_TEST(caught);
    OE_TEST(dynamic_cast_works);
    OE_TEST(num_constructions == 6);
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

    /*
       Some expection test will fail in simulation mode, due to the failure of
       isolation of exception in enclave then host process will be terminated.
    */
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0 &&
        strstr(argv[1], "global_init_exception_enc") != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(global_init_exception_enc)\n");
        return SKIP_RETURN_CODE;
    }

    result = oe_create_stdcxx_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (strcmp(argv[2], oe_result_str(OE_ENCLAVE_ABORTING)) == 0)
    {
        if (strcmp(oe_result_str(result), argv[2]) == 0)
        {
            printf(
                "=== Passed: enclave not created, enclave status: (%s)\n",
                oe_result_str(result));
        }
        else
        {
            oe_put_err("oe_create_stdcxx_enclave(): result=%u", result);
        }
    }
    else if (strcmp(argv[2], oe_result_str(OE_OK)) == 0)
    {
        if (strcmp(oe_result_str(result), argv[2]) == 0)
        {
            test_stdcxx(enclave);
            printf("=== passed all tests (%s)\n", argv[0]);
        }
        else
        {
            oe_put_err("oe_create_stdcxx_enclave(): result=%u", result);
        }
    }
    else
    {
        oe_put_err("Invalid argument: %s", argv[2]);
    }

    if (enclave)
    {
        if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        {
            oe_put_err("oe_terminate_enclave(): result=%u", result);
        }
    }

    return 0;
}
