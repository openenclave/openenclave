// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ecalls.h"
#include <stdio.h>

/**
 * Fetch the quoted public key from the enclave.
 */
QuotedPublicKey* GetPublicKey(oe_enclave_t* enclave)
{
    GetPublicKeyArgs args = {};
    oe_result_t result = oe_call_enclave(enclave, "GetPublicKey", &args);
    if (result != OE_OK || !args.success || args.quotedPublicKey == NULL)
    {
        printf("GetPublicKey failed. %s", oe_result_str(result));
        exit(1);
    }

    printf("GetPublicKey succeeded.\n");
    return args.quotedPublicKey;
}

/**
 * Ask the enclave to attest and store the public key of another enclave.
 */
void StorePublicKey(oe_enclave_t* enclave, QuotedPublicKey* quotedPublicKey)
{
    StorePublicKeyArgs args = {};
    args.quotedPublicKey = quotedPublicKey;
    oe_result_t result = oe_call_enclave(enclave, "StorePublicKey", &args);
    if (result != OE_OK || !args.success)
    {
        printf("StorePublicKey failed. %s", oe_result_str(result));
        exit(1);
    }

    printf("StorePublicKey succeeded.\n");
}

/**
 * Fetch encrypted data from the enclave.
 */
void GenerateEncryptedData(oe_enclave_t* enclave, uint8_t** data, size_t* size)
{
    GenerateEncryptedDataArgs args = {};
    oe_result_t result =
        oe_call_enclave(enclave, "GenerateEncryptedData", &args);
    if (result != OE_OK || !args.success || args.data == NULL)
    {
        printf("GenerateEncryptedData failed. %s", oe_result_str(result));
        exit(1);
    }
    *data = args.data;
    *size = args.size;

    printf("GenerateEncryptedData succeeded.\n");
}

/**
 * Send encrypted data to the enclave.
 */
void ProcessEncryptedData(
    oe_enclave_t* enclave,
    const uint8_t* data,
    size_t size)
{
    ProcessEncryptedDataArgs args = {};
    args.data = data;
    args.size = size;

    oe_result_t result =
        oe_call_enclave(enclave, "ProcessEncryptedData", &args);
    if (result != OE_OK || !args.success)
    {
        printf("ProcessEncryptedData failed. %s", oe_result_str(result));
        exit(1);
    }

    printf("ProcessEncryptedData succeeded.\n");
}
