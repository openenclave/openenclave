// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "stdc_u.h"

#if 0
#define ECHO
#endif

uint64_t prev;

void TestStdc(oe_enclave_t* enclave)
{
    printf("=== %s() \n", __FUNCTION__);
    int rval = 0;
    char buf1[BUFSIZE];
    char buf2[BUFSIZE];

    oe_result_t result = test(enclave, &rval, buf1, buf2);
    OE_TEST(result == OE_OK);
    OE_TEST(strcmp(buf1, "AAABBBCCC") == 0);
    OE_TEST(strcmp(buf2, "value=100") == 0);
    OE_TEST(rval);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    oe_enclave_t* enclave = NULL;

    oe_result_t result = oe_create_stdc_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_create_stdc_enclave(): result=%u", result);
    }

    TestStdc(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
