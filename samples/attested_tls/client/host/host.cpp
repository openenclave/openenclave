// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "tls_client_u.h"

#define TLS_SERVER_NAME "localhost"
#define TLS_SERVER_PORT "12340"

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_tls_client_enclave(
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
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    char* server_name = NULL;
    char* server_port = NULL;

    /* Check argument count */
    if (argc != 4)
    {
    print_usage:
        printf(
            "Usage: %s TLS_SERVER_ENCLAVE_PATH -server:<name> -port:<port>\n",
            argv[0]);
        return 1;
    }
    // read server name  parameter
    {
        const char* option = "-server:";
        int param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[2], option, param_len) == 0)
        {
            server_name = (char*)(argv[2] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }
    printf("server name = [%s]\n", server_name);

    // read port parameter
    {
        const char* option = "-port:";
        int param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[3], option, param_len) == 0)
        {
            server_port = (char*)(argv[3] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }
    printf("server port = [%s]\n", server_port);

    printf("Host: Creating two enclaves\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
    {
        goto exit;
    }

    printf("Host: launch TLS client to initiate TLS connection\n");
    ret = launch_tls_client(enclave, &ret, server_name, server_port);
    if (ret != 0)
    {
        printf("Host: launch_tls_client failed\n");
        goto exit;
    }
    ret = 0;
exit:

    if (enclave)
        terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
