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

void TestStdc(oe_enclave_t* enclave)
{
    oe_result_t result;
    TestArgs args;

    printf("=== %s() \n", __FUNCTION__);
    result = oe_call_enclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(strcmp(args.buf1, "AAABBBCCC") == 0);
    OE_TEST(strcmp(args.buf2, "value=100") == 0);
    OE_TEST(args.strdup_ok);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    TestStdc(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
