// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "../args.h"

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    Args args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;

    if ((result = OE_CallEnclave(enclave, "Test", &args)) != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL failed args.result=%d", args.ret);

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
