/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include <openenclave/host.h>
#include "SampleTA_u.h"

#ifdef USE_SGX
# define TA_ID "SampleTA" /* DLL will be SampleTA.signed.dll */
#endif
#ifdef USE_OPTEE
# define TA_ID "aac3129e-c244-4e09-9e61-d4efcf31bca3"
#endif

int main(int argc, char** argv)
{
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = OE_ENCLAVE_FLAG_SERIALIZE_ECALLS;

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "/?") == 0)) {
        printf("Usage: SampleServerApp port\n\n");
        printf("    Acts as an echo server.\n");
        return 0;
    }
    char* port = (argc == 2) ? argv[1] : "12345";

#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    oe_result_t result = oe_create_SampleTA_enclave(TA_ID, 
                                                    0,
                                                    enclave_flags,
                                                    NULL,
                                                    0,
                                                    &enclave);
    if (result != OE_OK) {
        printf("Error %u creating TA\n", result);
        return 1;
    }

    char serv[256];
    strcpy_s(serv, sizeof(serv), port);

    /* TrustZone only allows one thread per TA at a time.
     * To simulate that behavior for SGX as well, we take a mutex.
     * The acquire/release should really be moved inside the generated code,
     * and treated as internal.
     */
    int status;
    oe_acquire_enclave_mutex(enclave);
    result = ecall_RunServer(enclave, &status, serv);
    oe_release_enclave_mutex(enclave);

    if (result != OE_OK)
    {
        printf("Error %u trying to reach the TA\n", result);
        return 1;
    }
    if (status != 0) {
        printf("Error %#x running server\n", status);
        return 1;
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK) {
        printf("Error %u destroying TA\n", result);
        return 1;
    }

    printf("Success, hit enter to quit:");
    gets();
    return 0;
}
