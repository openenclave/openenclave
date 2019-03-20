/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <assert.h>
#ifdef LINUX
#include <stdext.h>
#include <unistd.h>
#else
#include <windows.h>
#endif  // LINUX
#include <openenclave/host.h>
#include "sockets_u.h"

#ifdef OE_USE_SGX
# define TA_ID "sockets_enclave" /* DLL will be sockets_enclave.signed.dll */
#endif
#ifdef OE_USE_OPTEE
# define TA_ID "aac3129e-c244-4e09-9e61-d4efcf31bca3"
#endif

int main(int argc, char** argv)
{
    char dummy[256];
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = OE_ENCLAVE_FLAG_SERIALIZE_ECALLS;

    if (argc != 3 && argc != 1) {
        printf("Usage: socketclient_host servername port\n\n");
        printf("    Acts as an echo client.\n");
        return 0;
    }
    const char* servername = (argc > 1) ? argv[1] : "localhost";
    const char* port = (argc > 2) ? argv[2] : "12345";

#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    oe_result_t result = oe_create_sockets_enclave(TA_ID, 
                                                   OE_ENCLAVE_TYPE_DEFAULT,
                                                   enclave_flags,
                                                   NULL,
                                                   0,
                                                   &enclave);
    if (result != OE_OK) {
        printf("Error %u creating TA\n", result);
        return 1;
    }

    char serv[256];
    char server[256];
    strcpy_s(server, sizeof(server), servername);
    strcpy_s(serv, sizeof(serv), port);

    /* TrustZone only allows one thread per TA at a time.
     * To simulate that behavior for SGX as well, we take a mutex.
     * The acquire/release should really be moved inside the generated code,
     * and treated as internal.
     */
    int status;
    oe_acquire_enclave_mutex(enclave);
    do
    {
        result = ecall_RunClient(enclave, &status, server, serv);
#ifdef WIN32
        Sleep(1000);
#else
        usleep(1000000);
#endif
    } while (result == OE_OK && status == 0);
    oe_release_enclave_mutex(enclave);

    if (result != OE_OK)
    {
        printf("Error %u trying to reach the TA\n", result);
        return 1;
    }
    if (status != 0) {
        printf("Error %#x running client\n", status);
        return 1;
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK) {
        printf("Error %u destroying TA\n", result);
        return 1;
    }

    printf("Success, hit enter to quit:");
    fgets(dummy, sizeof(dummy), stdin);
    return 0;
}
