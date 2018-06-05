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

void TestPrint(OE_Enclave* enclave)
{
    OE_Result result;
    TestPrintArgs args;

    printf("=== %s() \n", __FUNCTION__);
    args.rc = -1;
    result = OE_CallEnclave(enclave, "TestPrint", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.rc == 0);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    TestPrint(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
