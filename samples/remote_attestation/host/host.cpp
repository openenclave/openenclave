// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "remoteattestation_u.h"

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_remoteattestation_enclave(
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
    oe_enclave_t* enclave_a = NULL;
    oe_enclave_t* enclave_b = NULL;
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    uint8_t* encrypted_key = NULL;
    size_t encrypted_key_size = 0;

    /* Check argument count */
    if (argc != 3)
    {
        printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf("Host: Creating two enclaves\n");
    enclave_a = create_enclave(argv[1]);
    if (enclave_a == NULL)
    {
        goto exit;
    }
    enclave_b = create_enclave(argv[2]);
    if (enclave_b == NULL)
    {
        goto exit;
    }

    printf("Host: requesting a remote report and the encryption key from 1st "
           "enclave\n");
    result = get_remote_report_with_pubkey(
        enclave_a,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: 1st enclave's public key: \n%s", pem_key);

    printf("Host: requesting 2nd enclave to attest 1st enclave's the remote "
           "report and the public key\n");
    result = verify_report_and_set_pubkey(
        enclave_b,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    printf("Host: Requesting a remote report and the encryption key from "
           "2nd enclave=====\n");
    result = get_remote_report_with_pubkey(
        enclave_b,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: 2nd enclave's public key: \n%s", pem_key);

    printf("Host: Requesting first enclave to attest 2nd enclave's "
           "remote report and the public key=====\n");
    result = verify_report_and_set_pubkey(
        enclave_a,
        &ret,
        pem_key,
        pem_key_size,
        remote_report,
        remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(remote_report);
    remote_report = NULL;

    // Establish secure channel using an ephemeral symmetric key, encrypted and
    // signed
    printf(
        "Host: Requesting secure channel to be established from 1st enclave\n");
    result = establish_secure_channel(
        enclave_a, &ret, &encrypted_key, &encrypted_key_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: establish_secure_channel failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf(
        "Received encrypted data to establish secure channel of size = %ld\n",
        encrypted_key_size);

    printf("Host: Requesting 2nd enclave to acknowledge secure channel\n");
    result = acknowledge_secure_channel(
        enclave_b, &ret, encrypted_key, encrypted_key_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: acknowledge_secure_channel failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    // exchange data between enclaves, securely
    printf("Host: Requesting encrypted message from 1st enclave\n");
    result = generate_encrypted_message(
        enclave_a, &ret, &encrypted_msg, &encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_encrypted_message failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: Sending the encrypted message to 2nd enclave\n");
    result = process_encrypted_msg(
        enclave_b, &ret, encrypted_msg, encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: process_encrypted_msg failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: Success\n");

    // Free host memory allocated by the first enclave
    free(encrypted_msg);
    encrypted_msg = NULL;

    printf("Host: Requesting encrypted message from 2nd enclave\n");
    result = generate_encrypted_message(
        enclave_b, &ret, &encrypted_msg, &encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_encrypted_message failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Sending encrypted message to 1st  enclave=====\n");
    result = process_encrypted_msg(
        enclave_a, &ret, encrypted_msg, encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "host process_encrypted_msg failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: Success\n");

    // Free host memory allocated by the enclave.
    free(encrypted_msg);
    encrypted_msg = NULL;
    ret = 0;

exit:
    if (pem_key)
        free(pem_key);

    if (remote_report)
        free(remote_report);

    if (encrypted_msg != NULL)
        free(encrypted_msg);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
