// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "ecalls.h"

oe_enclave_t* CreateEnclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf("oe_create_enclave failed. %s", oe_result_str(result));
        exit(1);
    }

    printf("Enclave created.\n");
    return enclave;
}

void TerminateEnclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Enclave terminated.\n");
}

int main(int argc, const char* argv[])
{
    /* Check argument count */
    if (argc != 2)
    {
        printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf("\n\n=====Creating two enclaves=====\n");

    oe_enclave_t* enclave1 = CreateEnclave(argv[1]);
    oe_enclave_t* enclave2 = CreateEnclave(argv[1]);

    printf(
        "\n\n=====Requesting quoted encryption key from first enclave=====\n");
    QuotedPublicKey* quoted_public_key = GetPublicKey(enclave1);
    printf("First enclave's public key: \n%s", quoted_public_key->pem_key);

    printf(
        "\n\n=====Requesting second enclave to attest first enclave's "
        "quoted public key=====\n");
    StorePublicKey(enclave2, quoted_public_key);

    // Free host memory allocated by the enclave.
    free(quoted_public_key);

    printf(
        "\n\n=====Requesting quoted encryption key from second enclave=====\n");
    quoted_public_key = GetPublicKey(enclave2);
    printf("Second enclave's public key: \n%s", quoted_public_key->pem_key);

    printf(
        "\n\n=====Requesting first enclave to attest second enclave's "
        "quoted public key=====\n");
    StorePublicKey(enclave1, quoted_public_key);

    // Free host memory allocated by the enclave.
    free(quoted_public_key);

    uint8_t* encrypted_data = NULL;
    uint32_t encrypted_data_size = 0;
    printf("\n\n=====Requesting encrypted data from first enclave=====\n");
    GenerateEncryptedData(enclave1, &encrypted_data, &encrypted_data_size);

    printf("\n\n=====Sending encrypted data to second enclave=====\n");
    ProcessEncryptedData(enclave2, encrypted_data, encrypted_data_size);

    // Free host memory allocated by the enclave.
    free(encrypted_data);

    printf("\n\n=====Requesting encrypted data from second enclave=====\n");
    GenerateEncryptedData(enclave2, &encrypted_data, &encrypted_data_size);

    printf("\n\n=====Sending encrypted data to first enclave=====\n");
    ProcessEncryptedData(enclave1, encrypted_data, encrypted_data_size);

    // Free host memory allocated by the enclave.
    free(encrypted_data);

    printf("\n\n=====Terminating enclaves.=====\n");
    TerminateEnclave(enclave1);
    TerminateEnclave(enclave2);

    printf("\n\n=====Done=====\n");

    return 0;
}
