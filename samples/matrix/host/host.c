// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>

#include "../common/multiply.h"
#include "matrix_u.h"

bool check_simulate_opt(int* argc, const char* argv[])
{
    for (int i = 0; i < *argc; i++)
    {
        if (strcmp(argv[i], "--simulate") == 0)
        {
            fprintf(stdout, "Running in simulation mode\n");
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return true;
        }
    }
    return false;
}

// This is the function that the enclave will call back into to
// print a message.
void host_matrix()
{
    fprintf(stdout, "Enclave called into host to print: Finished matrix!\n");
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (check_simulate_opt(&argc, argv))
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if (argc != 2)
    {
        fprintf(
            stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
        goto exit;
    }

    // Run the multiplication task first for comparison with enclave in VTune
    task();

    // Create the enclave
    result = oe_create_matrix_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_matrix_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    // Call into the enclave
    result = enclave_matrix(enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_matrix failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
