// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libgen.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "oegencert_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave;
    int retval;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    char path[PATH_MAX];

    /* Disable logging. */
    setenv("OE_LOG_LEVEL", "NONE", 1);

    if (argc != 1)
    {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        return 1;
    }

    /* Deduce enclave path from host path */
    {
        char* clone;
        const char* root;

        if (!(clone = strdup(argv[0])))
        {
            fprintf(stderr, "%s: calloc() failed\n", argv[0]);
            exit(1);
        }

        if (!(root = dirname(clone)))
        {
            fprintf(stderr, "%s: dirname() failed\n", argv[0]);
            exit(1);
        }

        snprintf(path, sizeof(path), "%s/oegencert_enclave", root);

        free(clone);
    }

    r = oe_create_oegencert_enclave(path, type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: failed create enclave: %s\n", argv[0], argv[1]);
        exit(1);
    }

    r = oegencert_ecall(enclave, &retval);

    if (r != OE_OK || retval != 0)
    {
        fprintf(stderr, "%s: failed to generate certificate\n", argv[0]);
        exit(1);
    }

    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: failed to terminate enclave\n", argv[0]);
        exit(1);
    }

    return 0;
}
