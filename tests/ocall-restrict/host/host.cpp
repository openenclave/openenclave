// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

static OE_Enclave* enclave;

OE_OCALL void TestEcall(void* args)
{
    TestORArgs* ta = (TestORArgs*)args;

    printf("%s(): Called\n", __FUNCTION__);

    ta->result = OE_CallEnclave(enclave, "ECallNested", NULL);

    printf("%s(): Returning ta->result=%x\n", __FUNCTION__, ta->result);
}

int main(int argc, const char* argv[])
{
    OE_Result result;

    TestORArgs ta;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(
             argv[1], OE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
        return 1;
    }

    ta.result = OE_FAILURE;
    /* Invoke tests */
    {
        OE_Result result = OE_CallEnclave(enclave, "Test", &ta);
        OE_TEST(result == OE_OK);
        OE_TEST(ta.result == OE_OK);
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
