// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "ecalls.h"

oe_enclave_t* CreateEnclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Enclave library %s\n", enclave_path);
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
    }
    else
    {
        printf("Enclave created.\n");
    }
    return enclave;
}

void TerminateEnclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Enclave terminated.\n");
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave1 = NULL;
    oe_enclave_t* enclave2 = NULL;
    RemoteReportWithPubKey* report_with_pub_key1 = NULL;
    RemoteReportWithPubKey* report_with_pub_key2 = NULL;
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;

    /* Check argument count */
    if (argc != 3)
    {
        printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf("\n\n=====Creating two enclaves=====\n");

    enclave1 = CreateEnclave(argv[1]);
    if (enclave1 == NULL)
    {
        goto exit;
    }
    enclave2 = CreateEnclave(argv[2]);
    if (enclave2 == NULL)
    {
        goto exit;
    }

    printf(
        "\n\n=====Requesting a remote report and the encryption key from "
        "first enclave=====\n");
    report_with_pub_key1 = GetRemoteReportWithPubKey(enclave1);
    printf("First enclave's public key: \n%s", report_with_pub_key1->pem_key);

    printf(
        "\n\n=====Requesting second enclave to attest first enclave's "
        "the remote report and the public key=====\n");
    result = VerifyReportAndSetPubKey(enclave2, report_with_pub_key1);
    if (result != OE_OK)
    {
        printf("VerifyReportAndSetPubKey failed. %s", oe_result_str(result));
        goto exit;
    }

    printf(
        "\n\n=====Requesting a remote report and the encryption key from "
        "second enclave=====\n");
    report_with_pub_key2 = GetRemoteReportWithPubKey(enclave2);
    printf("Second enclave's public key: \n%s", report_with_pub_key2->pem_key);

    printf(
        "\n\n=====Requesting first enclave to attest second enclave's "
        "remote report and the public key=====\n");
    result = VerifyReportAndSetPubKey(enclave1, report_with_pub_key2);
    if (result != OE_OK)
    {
        printf("VerifyReportAndSetPubKey failed. %s", oe_result_str(result));
        goto exit;
    }

    // exchange data between enclaves, securely

    printf("\n\n=====Requesting encrypted message from first enclave=====\n");
    result =
        GenerateEncryptedMessage(enclave1, &encrypted_msg, &encrypted_msg_size);
    if (result != OE_OK)
    {
        printf("GenerateEncryptedMessage failed. %s", oe_result_str(result));
        goto exit;
    }

    printf("\n\n=====Sending encrypted message to second enclave=====\n");
    result = ProcessEncryptedMessage(enclave2, encrypted_msg, encrypted_msg_size);
    if (result != OE_OK)
    {
        printf("ProcessEncryptedMessage failed. %s", oe_result_str(result));
        goto exit;
    }

    // Free host memory allocated by the enclave
    free(encrypted_msg);
    encrypted_msg = NULL;

    printf("\n\n=====Requesting encrypted message from second enclave=====\n");
    result =
        GenerateEncryptedMessage(enclave2, &encrypted_msg, &encrypted_msg_size);
    if (result != OE_OK)
    {
        printf("GenerateEncryptedMessage failed. %s", oe_result_str(result));
        goto exit;
    }

    printf("\n\n=====Sending encrypted message to first enclave=====\n");
    result = ProcessEncryptedMessage(enclave1, encrypted_msg, encrypted_msg_size);
    if (result != OE_OK)
    {
        printf("ProcessEncryptedMessage failed. %s", oe_result_str(result));
        goto exit;
    }

    // Free host memory allocated by the enclave.
    free(encrypted_msg);
    encrypted_msg = NULL;
    ret = 0;

exit:

    if (encrypted_msg != NULL)
        free(encrypted_msg);

    // Free host memory allocated by the enclave.
    if (report_with_pub_key1)
        free(report_with_pub_key1);
    if (report_with_pub_key2)
        free(report_with_pub_key2);

    printf("\n\n=====Terminating enclaves.=====\n");
    if (enclave1)
        TerminateEnclave(enclave1);

    if (enclave2)
        TerminateEnclave(enclave2);

    printf("\n\n=====Done with %s =====\n", (ret == 0) ? "success" : "failure");
    return ret;
}
