// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "../args.h"

#define SKIP_RETURN_CODE 2

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
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode (sealKey)\n");
        return SKIP_RETURN_CODE;
    }

    printf("=== This program is used to test enclave seal key functions.\n");

    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
        return 1;
    }

    SealKeyArgs args;
    args.ret = -1;
    result = OE_CallEnclave(enclave, "TestSealKey", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.ret == 0);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
        return 1;
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
