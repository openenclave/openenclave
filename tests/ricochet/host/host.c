// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../args.h"

static oe_enclave_t* enclave = NULL;

OE_OCALL void Ricochet(void* args_)
{
    RicochetArgs* args = (RicochetArgs*)args_;

    printf("Host Ricochet(): i=%d\n", args->i);

    if (args->i < args->count)
    {
        args->i++;
        oe_result_t result = oe_call_enclave(enclave, "Ricochet", args);
        OE_TEST(result == OE_OK);
    }
}

int main(int argc, const char* argv[])
{
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    for (size_t i = 0; i < 3; i++)
    {
        RicochetArgs args;
        args.i = 0;
        args.count = 16;

        if ((result = oe_call_enclave(enclave, "Ricochet", &args)) != OE_OK)
            oe_put_err("oe_call_enclave() failed: result=%u", result);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
