// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/host.h>

#include <openenclave/internal/tests.h>

#include <stdlib.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "threadpool_u.h"

#define SKIP_RETURN_CODE 2

typedef struct _input_params
{
    const char* enclave_filename;
} input_params_t;

static input_params_t _params;

static int _parse_args(int argc, const char* argv[])
{
    // parse 5 required arguments
    if (argc != 2)
    {
        printf("Usage: %s <enclave file>\n", argv[0]);
        return -1;
    }

    // parse 1 argument, the enclave file
    const char* enclave_file = argv[1];
    if (strlen(enclave_file) == 0)
    {
        printf("Invalid enclave file: %s\n", enclave_file);
        return -1;
    }
    _params.enclave_filename = enclave_file;

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_UNEXPECTED;

    oe_enclave_t* enclave = nullptr;

    int ret = _parse_args(argc, argv);
    if (ret != 0)
    {
        printf("Failed to parse arguments\n");
        goto done;
    }

    if ((oe_get_create_flags() & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode (%s)\n", argv[0]);
        ret = SKIP_RETURN_CODE;
        goto done;
    }

    if ((result = oe_create_threadpool_enclave(
             _params.enclave_filename,
             OE_ENCLAVE_TYPE_AUTO,
             OE_ENCLAVE_FLAG_DEBUG,
             nullptr,
             0,
             &enclave)) != OE_OK)
    {
        printf(
            "Failed to create enclave. result=%u (%s)\n",
            result,
            oe_result_str(result));
        ret = 1;
        goto done;
    }

    // Init Enclave
    {
        oe_result_t result = OE_UNEXPECTED;
        enclave_init(enclave, &result);
        if (result != OE_OK)
        {
            printf(
                "Failed to init enclave. result=%u (%s)\n",
                result,
                oe_result_str(result));
            ret = 1;
            goto done;
        }
    }

    // Create multiple enclave threads
    {
        // todo
    }

done:
    if (enclave)
    {
        // Shutdown Enclave
        {
            oe_result_t result = OE_UNEXPECTED;
            enclave_shutdown(enclave, &result);
            if (result != OE_OK)
            {
                printf(
                    "Failed to shutdown enclave. result=%u (%s)\n",
                    result,
                    oe_result_str(result));
                ret = 1;
            }
        }

        oe_terminate_enclave(enclave);
    }

    return ret;
}
