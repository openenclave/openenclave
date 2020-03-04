// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "host.h"

int main(int argc, const char* argv[])
{
    int result = create_enclave(argc, argv);
    if (result != 0)
    {
        fprintf(stderr, "Failed to create enclave with result = %i.\n", result);

        return result;
    }

    char* enclaveMessage = (char*)malloc(ENCLAVE_MESSAGE_SIZE * sizeof(char));
    if (enclaveMessage == NULL)
    {
        fprintf(stderr, "Failed to allocate enclave message.\n");

        terminate_enclave();
        return ENOMEM;
    }

    result = call_enclave(
        "\"Process In Enclave\"", enclaveMessage, ENCLAVE_MESSAGE_SIZE);
    if (result != 0)
    {
        fprintf(stderr, "Failed to call enclave with result = %i.\n", result);

        terminate_enclave();
        return result;
    }

    result = terminate_enclave();
    if (result != 0)
    {
        fprintf(
            stderr, "Failed to terminate enclave with result = %i.\n", result);
    }

    return result;
}
