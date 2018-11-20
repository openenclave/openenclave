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

/* This function called by test_callback() ECALL */
OE_OCALL void callback(void* arg, oe_enclave_t* enclave)
{
    test_callback_args_t* args = (test_callback_args_t*)arg;

    if (args)
        args->out = args->in;
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
        oe_put_err("oe_create_enclave(): result=%u", result);

    /* Test oe_call_host_by_address() by having enclave invoke host callback */
    {
        const uint64_t VALUE = 0xec39cae11f9b4e26;
        test_callback_args_t args;

        args.callback = callback;
        args.in = VALUE;
        args.out = 0;
        OE_TEST(oe_call_enclave(enclave, "test_callback", &args) == OE_OK);
        OE_TEST(args.in == VALUE);
        OE_TEST(args.out == VALUE);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
