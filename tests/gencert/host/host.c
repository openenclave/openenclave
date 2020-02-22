// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "oegencert_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave;
    int retval;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    /* Disable logging. */
    setenv("OE_LOG_LEVEL", "NONE", 1);

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result =
        oe_create_oegencert_enclave(argv[1], type, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: failed create enclave: %s\n", argv[0], argv[1]);
        exit(1);
    }

    result = oegencert_ecall(enclave, &retval);

    if (result != OE_OK || retval != 0)
    {
        fprintf(stderr, "%s: failed to generate certificate\n", argv[0]);
        exit(1);
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: failed to terminate enclave\n", argv[0]);
        exit(1);
    }

    return 0;
}
