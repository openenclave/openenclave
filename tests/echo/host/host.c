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

OE_OCALL void Echo(void* args_)
{
    EchoArgs* args = (EchoArgs*)args_;

    OE_TEST(strcmp(args->str1, "oe_host_stack_strdup1") == 0);
    OE_TEST(strcmp(args->str2, "oe_host_stack_strdup2") == 0);
    OE_TEST(strcmp(args->str3, "oe_host_stack_strdup3") == 0);

    if (!(args->out = oe_strdup(args->in)))
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    EchoArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    if (!(args.in = oe_strdup("Hello World")))
        oe_put_err("Strdup() failed");

    if ((result = oe_call_enclave(enclave, "Echo", &args)) != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (args.ret != 0)
        oe_put_err("ECALL failed args.result=%d", args.ret);

    OE_TEST(args.in);
    OE_TEST(args.out);

    if (strcmp(args.in, args.out) != 0)
        oe_put_err("ecall failed: %s != %s\n", args.in, args.out);

    free((char*)args.in);
    free((char*)args.out);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (echo)\n");

    return 0;
}
