// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


#include <openenclave/host.h>
#include <stdio.h>

OE_OCALL void HostEcho(void* args)
{
    if (args)
    {
        const char* str = (const char*)args;
        printf("%s\n", str);
    }
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

    result = oe_create_enclave(
        argv[1],
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        fprintf(stderr, "%s: oe_create_enclave(): %u\n", argv[0], result);
        return 1;
    }

    result = oe_call_enclave(enclave, "EnclaveEcho",  (void*)"Hello Open Encalve SDK!");
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: oe_call_enclave(): %u\n", argv[0], result);
        return 1;
    }

    oe_terminate_enclave(enclave);

    return 0;
}

