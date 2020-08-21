// Copyright (c) Open Enclave SDK contributors.
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
            "Host: oe_create_local_attestation_enclave failed. %s",
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
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* format_settings = NULL;
    size_t format_settings_size = 0;

    printf(
        "\n\nHost: ********** Attest  %s to %s **********\n\n",
        enclave_b_name,
        enclave_a_name);

    printf("Host: Requesting %s format settings\n", enclave_a_name);
    result = get_enclave_format_settings(
        enclave_a, &ret, &format_settings, &format_settings_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Host: get_format_settings failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf(
        "Host: Requesting %s to generate a targeted evidence with an "
        "encryption key\n",
        enclave_b_name);
    result = get_targeted_evidence_with_public_key(
        enclave_b,
        &ret,
        format_settings,
        format_settings_size,
        &pem_key,
        &pem_key_size,
        &evidence,
        &evidence_size);

    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: get_targeted_evidence_with_public_key failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: %s's  public key: \n%s\n", enclave_b_name, pem_key);
    printf("Host: verify_evidence_and_set_public_key in %s\n", enclave_a_name);
    result = verify_evidence_and_set_public_key(
        enclave_a, &ret, pem_key, pem_key_size, evidence, evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

exit:
    free(pem_key);
    free(evidence);
    free(format_settings);
    return ret;
}
int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave_a = NULL;
    oe_enclave_t* enclave_b = NULL;
    uint8_t* encrypted_message = NULL;
    size_t encrypted_message_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;

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

    // attest enclave 2 to enclave 1
    ret = attest_one_enclave_to_the_other(
        "enclave_a", enclave_a, "enclave_b", enclave_b);
    if (ret)
    {
        printf("Host: attestation failed with %d\n", ret);
        goto exit;
    }

    // attest enclave 1 to enclave 2
    ret = attest_one_enclave_to_the_other(
        "enclave_b", enclave_b, "enclave_a", enclave_a);
    if (ret)
    {
        printf("Host: attestation failed with %d\n", ret);
        goto exit;
    }

    // With successfully attestation on each other, we are ready to exchange
    // data between enclaves, securely via asymmetric encryption
    printf("Host: Requesting encrypted message from 1st enclave\n");
    result = generate_encrypted_message(
        enclave_a, &ret, &encrypted_message, &encrypted_message_size);
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
    result = process_encrypted_message(
        enclave_b, &ret, encrypted_message, encrypted_message_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: process_encrypted_message failed. %s",
            oe_result_str(result));
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
    free(encrypted_message);
    encrypted_message = NULL;

    printf("Host: Requesting encrypted message from 2nd enclave\n");
    result = generate_encrypted_message(
        enclave_b, &ret, &encrypted_message, &encrypted_message_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_encrypted_message failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Sending encrypted message to 1st enclave=====\n");
    result = process_encrypted_message(
        enclave_a, &ret, encrypted_message, encrypted_message_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "host process_encrypted_message failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: Success\n");

    // Free host memory allocated by the enclave.
    free(encrypted_message);
    encrypted_message = NULL;
    ret = 0;

exit:

    if (encrypted_message != NULL)
        free(encrypted_message);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
