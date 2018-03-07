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

OE_OCALL void Echo(void* args_)
{
    EchoArgs* args = (EchoArgs*)args_;

    assert(strcmp(args->str1, "OE_HostStackStrdup1") == 0);
    assert(strcmp(args->str2, "OE_HostStackStrdup2") == 0);
    assert(strcmp(args->str3, "OE_HostStackStrdup3") == 0);

    if (!(args->out = OE_Strdup(args->in)))
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}

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

    EchoArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    if (!(args.in = OE_Strdup("Hello World")))
        OE_PutErr("Strdup() failed");

    if ((result = OE_CallEnclave(enclave, "Echo", &args)) != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL failed args.result=%d", args.ret);

    assert(args.in);
    assert(args.out);

    if (strcmp(args.in, args.out) != 0)
        OE_PutErr("ecall failed: %s != %s\n", args.in, args.out);

    free((char*)args.in);
    free((char*)args.out);

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
