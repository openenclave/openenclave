// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>

OE_OCALL void host_hello(void* args_)
{
    fprintf(stdout, "Enclave called into host to print: Hello World!\n");
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s enclave_image_path\n", argv[0]);
        goto exit;
    }

    result = oe_create_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "oe_create_enclave(): result=%u", result);
        goto exit;
    }

    result = oe_call_enclave(enclave, "enclave_helloworld", NULL);
    if (result != OE_OK)
    {
        fprintf(stderr, "failed: result=%u", result);
        goto exit;
    }
    ret = 0;

exit:
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
