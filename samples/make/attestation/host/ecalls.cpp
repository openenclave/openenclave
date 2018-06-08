// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ecalls.h"
#include <stdio.h>

/**
 * Initialize the enclave.
 */
void Initialize(OE_Enclave* enclave)
{
    OE_Result result = OE_CallEnclave(enclave, "Initialize", NULL);
    if (result != OE_OK)
    {
        printf("Initialize failed. %s", OE_ResultStr(result));
        exit(1);
    }

    printf("Enclave Initialized.\n");
}

/**
 * Fetch the quoted public key from the enclave.
 */
QuotedPublicKey* GetPublicKey(OE_Enclave* enclave)
{
    GetPublicKeyArgs args = {};
    OE_Result result = OE_CallEnclave(enclave, "GetPublicKey", &args);
    if (result != OE_OK || args.result != OE_OK || args.quotedPublicKey == NULL)
    {
        printf("GetPublicKey failed. %s", OE_ResultStr(result));
        exit(1);
    }

    printf("GetPublicKey succeeded.\n");
    return args.quotedPublicKey;
}

/**
 * Ask the enclave to attest and store the public key of another enclave.
 */
void StorePublicKey(OE_Enclave* enclave, QuotedPublicKey* quotedPublicKey)
{
    StorePublicKeyArgs args = {};
    args.quotedPublicKey = quotedPublicKey;
    OE_Result result = OE_CallEnclave(enclave, "StorePublicKey", &args);
    if (result != OE_OK || args.result != OE_OK)
    {
        printf("StorePublicKey failed. %s", OE_ResultStr(result));
        exit(1);
    }

    printf("StorePublicKey succeeded.\n");
}

/**
 * Fetch encrypted data from the enclave.
 */
void GenerateEncryptedData(OE_Enclave* enclave, uint8_t** data, uint32_t* size)
{
    GenerateEncryptedDataArgs args = {};
    OE_Result result = OE_CallEnclave(enclave, "GenerateEncryptedData", &args);
    if (result != OE_OK || args.result != OE_OK || args.data == NULL)
    {
        printf("GenerateEncryptedData failed. %s", OE_ResultStr(result));
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
    OE_Enclave* enclave,
    const uint8_t* data,
    uint32_t size)
{
    ProcessEncryptedDataArgs args = {};
    args.data = data;
    args.size = size;

    OE_Result result = OE_CallEnclave(enclave, "ProcessEncryptedData", &args);
    if (result != OE_OK || args.result != OE_OK)
    {
        printf("ProcessEncryptedData failed. %s", OE_ResultStr(result));
        exit(1);
    }

    printf("ProcessEncryptedData succeeded.\n");
}
