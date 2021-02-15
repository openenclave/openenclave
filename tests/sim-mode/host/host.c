// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sim_mode_u.h"

static void _launch_enclave_success(const char* path, const uint32_t flags)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_sim_mode_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_sim_mode_enclave(): result=%u", result);

    int ret;
    if ((result = test(enclave, &ret)) != OE_OK)
        oe_put_err("test: result=%u", result);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_ENCLAVE_FLAG_SIMULATE;

    _launch_enclave_success(argv[1], flags);

    return 0;
}
