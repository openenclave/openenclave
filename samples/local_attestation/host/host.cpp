// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "localattestation_u.h"

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_localattestation_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_localattestation_enclave failed. %s",
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

int attest_one_enclave_to_the_other(
    const char* enclave_a_name,
    oe_enclave_t* enclave_a,
    const char* enclave_b_name,
    oe_enclave_t* enclave_b)
{
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* target_info_buf = NULL;
    size_t target_info_size = 0;

    printf(
        "\n\nHost: ********** Attest  %s to %s **********\n\n",
        enclave_b_name,
        enclave_a_name);
    printf("Host: Requesting %s target info\n", enclave_a_name);
    result =
        get_target_info(enclave_a, &ret, &target_info_buf, &target_info_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Host: get_target_info failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf(
        "Host: Requesting %s to generate a targeted report with a encryption "
        "key\n",
        enclave_b_name);
    result = get_targeted_report_with_pubkey(
        enclave_b,
        &ret,
        target_info_buf,
        target_info_size,
        &pem_key,
        &pem_key_size,
        &report,
        &report_size);

    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: get_targeted_report_with_pubkey failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: %s's  public key: \n%s\n", enclave_b_name, pem_key);

    printf("Host: verify_report_and_set_pubkey in %s\n", enclave_a_name);
    result = verify_report_and_set_pubkey(
        enclave_a, &ret, pem_key, pem_key_size, report, report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_set_pubkey failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

exit:
    free(pem_key);
    free(report);
    free(target_info_buf), target_info_buf = NULL;
    return ret;
}
int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave1 = NULL;
    oe_enclave_t* enclave2 = NULL;
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

    printf("Host: Creating two enclaves\n");
    enclave1 = create_enclave(argv[1]);
    if (enclave1 == NULL)
    {
        goto exit;
    }
    enclave2 = create_enclave(argv[2]);
    if (enclave2 == NULL)
    {
        goto exit;
    }

    // attest enclave 2 to enclave 1
    ret = attest_one_enclave_to_the_other(
        "enclave1", enclave1, "enclave2", enclave2);
    if (ret)
    {
        printf("Host: attestation failed with %d\n", ret);
        goto exit;
    }

    // attest enclave 1 to enclave 2
    ret = attest_one_enclave_to_the_other(
        "enclave2", enclave2, "enclave1", enclave1);
    if (ret)
    {
        printf("Host: attestation failed with %d\n", ret);
        goto exit;
    }

    // With successfully attestation on each other, we are ready to exchange
    // data between enclaves, securely via asymmetric encryption
    printf("Host: Requesting encrypted message from 1st enclave\n");
    result = generate_encrypted_message(
        enclave1, &ret, &encrypted_msg, &encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_encrypted_message failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: Sending the encrypted message to 2nd enclave\n");
    result = process_encrypted_msg(
        enclave2, &ret, encrypted_msg, encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Host: process_encrypted_msg failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf(
        "\n***\nHost: Now both enclaves have attested each other.\n"
        "They can start exchanging messages between them \n"
        "using asymmetric encryption with the public keys exchanged earlier\n"
        "***\n\n");

    // Free host memory allocated by the first enclave
    free(encrypted_msg);
    encrypted_msg = NULL;

    printf("Host: Requesting encrypted message from 2nd enclave\n");
    result = generate_encrypted_message(
        enclave2, &ret, &encrypted_msg, &encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_encrypted_message failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Sending encrypted message to 1st  enclave=====\n");
    result = process_encrypted_msg(
        enclave1, &ret, encrypted_msg, encrypted_msg_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("host process_encrypted_msg failed. %s", oe_result_str(result));
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

    if (encrypted_msg != NULL)
        free(encrypted_msg);

    printf("Host: Terminating enclaves\n");
    if (enclave1)
        terminate_enclave(enclave1);

    if (enclave2)
        terminate_enclave(enclave2);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
