// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "tls_server_u.h"

#define LOOP_OPTION "-server-in-loop"

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_tls_server_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = OE_OK;
    int ret = 1;
    char* server_port = NULL;
    bool keep_server_up = false;

    /* Check argument count */
    if (argc != 3)
    {
        if (argc == 4)
        {
            if (strcmp(argv[3], LOOP_OPTION) != 0)
            {
                goto print_usage;
            }
            else
            {
                keep_server_up = true;
                goto read_port;
            }
        }
    print_usage:
        printf(
            "Usage: %s TLS_SERVER_ENCLAVE_PATH -port:<port> [%s]\n",
            argv[0],
            LOOP_OPTION);
        return 1;
    }

read_port:
    // read port parameter
    {
        char* option = (char*)"-port:";
        size_t param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[2], option, param_len) == 0)
        {
            server_port = (char*)(argv[2] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }
    printf("server port = %s\n", server_port);

    printf("Host: Creating an tls client enclave\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
    {
        goto exit;
    }

    printf("Host: calling setup_tls_server\n");
    ret = setup_tls_server(enclave, &ret, server_port, keep_server_up);
    if (ret != 0)
    {
        printf("Host: setup_tls_server failed\n");
        goto exit;
    }

exit:

    printf("Host: Terminating enclaves\n");
    if (enclave)
        terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
