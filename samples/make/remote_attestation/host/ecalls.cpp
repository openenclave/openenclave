// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ecalls.h"
#include <stdio.h>

/**
 * Fetch the remote report and public key from the enclave.
 */
RemoteReportWithPubKey* GetRemoteReportWithPubKey(oe_enclave_t* enclave)
{
    GetRemoteReportWithPubKeyArgs args = {};
    oe_result_t result =
        oe_call_enclave(enclave, "GetRemoteReportWithPubKey", &args);
    if (result != OE_OK || !args.success || args.reportWithPubKey == NULL)
    {
        printf("GetRemoteReportWithPubKey failed. %s", oe_result_str(result));
        exit(1);
    }

    printf("GetRemoteReportWithPubKey succeeded.\n");
    return args.reportWithPubKey;
}

/**
 * Ask the enclave to attest and store the public key of another enclave.
 */
oe_result_t VerifyReportAndSetPubKey(
    oe_enclave_t* enclave,
    RemoteReportWithPubKey* reportWithPubKey)
{
    VerifyReportWithPubKeyArgs args = {};
    args.reportWithPubKey = reportWithPubKey;
    oe_result_t result = OE_OK;

    result = oe_call_enclave(enclave, "VerifyReportAndSetPubKey", &args);
    if (result != OE_OK)
    {
        printf(
            "VerifyReportAndSetPubKey oe_call_enclave call failed. %s",
            oe_result_str(result));
        goto exit;
    }

    if (!args.success)
    {
        // oe_call_enclave call succeeded but the actual operation inside the
        // call failed
        printf("VerifyReportAndSetPubKey operation failed.");
        result = OE_FAILURE;
        goto exit;
    }
    result = OE_OK;
exit:
    return result;
}

/**
 * Fetch encrypted data from the enclave.
 */
oe_result_t GenerateEncryptedMessage(
    oe_enclave_t* enclave,
    uint8_t** data,
    size_t* size)
{
    GenerateEncryptedMessageArgs args = {};
    oe_result_t result = OE_OK;

    result = oe_call_enclave(enclave, "GenerateEncryptedMessage", &args);
    if (result != OE_OK)
    {
        printf(
            "GenerateEncryptedData oe_call_enclave failed: %s\n",
            oe_result_str(result));
        goto exit;
    }

    if (!args.success || args.data == NULL)
    {
        printf("GenerateEncryptedData operation failed.\n");
        result = OE_FAILURE;
        goto exit;
    }

    result = OE_OK;
    *data = args.data;
    *size = args.size;
    printf("GenerateEncryptedData succeeded.\n");
exit:
    return result;
}

/**
 * Send encrypted data to the enclave.
 */
oe_result_t ProcessEncryptedMessage(
    oe_enclave_t* enclave,
    const uint8_t* data,
    size_t size)
{
    ProcessEncryptedMessageArgs args = {};
    oe_result_t result = OE_OK;

    args.data = data;
    args.size = size;

    result = oe_call_enclave(enclave, "ProcessEncryptedMessage", &args);
    if (result != OE_OK)
    {
        printf(
            "ProcessEncryptedData oe_call_enclave failed: %s\n",
            oe_result_str(result));
        goto exit;
    }

    if (!args.success)
    {
        printf("ProcessEncryptedData failed.\n");
        result = OE_FAILURE;
        goto exit;
    }
    result = OE_OK;
    printf("ProcessEncryptedData succeeded.\n");

exit:
    return result;
}
