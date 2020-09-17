// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <stdio.h>
#include "attestation_u.h"

// SGX Local Attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
//
// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_attestation_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_attestation_enclave failed. %s",
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
    const oe_uuid_t* format_id,
    const char* attester_enclave_name,
    oe_enclave_t* attester_enclave,
    const char* verifier_enclave_name,
    oe_enclave_t* verifier_enclave)
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
        "\n\nHost: ********** Attest %s to %s **********\n\n",
        attester_enclave_name,
        verifier_enclave_name);

    printf("Host: Requesting %s format settings\n", verifier_enclave_name);
    result = get_enclave_format_settings(
        verifier_enclave,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);
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
        attester_enclave_name);
    result = get_evidence_with_public_key(
        attester_enclave,
        &ret,
        format_id,
        format_settings,
        format_settings_size,
        &pem_key,
        &pem_key_size,
        &evidence,
        &evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: get_evidence_with_public_key failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: %s's  public key: \n%s\n", attester_enclave_name, pem_key);

    printf(
        "Host: verify_evidence_and_set_public_key in %s\n",
        verifier_enclave_name);
    result = verify_evidence_and_set_public_key(
        verifier_enclave,
        &ret,
        format_id,
        pem_key,
        pem_key_size,
        evidence,
        evidence_size);
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
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    oe_uuid_t* format_id = nullptr;

    /* Check argument count */
    if (argc != 4)
    {
        printf("Usage: %s <tee> ENCLAVE_PATH1 ENCLAVE_PATH2\n", argv[0]);
        printf("       where <tee> is one of:\n");
        printf("           sgxlocal  : for SGX local attestation\n");
        printf("           sgxremote : for SGX remote attestation\n");
        return 1;
    }

    if (strcmp(argv[1], "sgxlocal") == 0)
    {
        format_id = &sgx_local_uuid;
    }
    else if (strcmp(argv[1], "sgxremote") == 0)
    {
        format_id = &sgx_remote_uuid;
    }
    else
    {
        printf("Unrecognized TEE type\n");
        return 1;
    }

    printf("Host: Creating two enclaves\n");
    enclave_a = create_enclave(argv[2], flags);
    if (enclave_a == NULL)
    {
        goto exit;
    }
    enclave_b = create_enclave(argv[3], flags);
    if (enclave_b == NULL)
    {
        goto exit;
    }

    // attest enclave A to enclave B
    ret = attest_one_enclave_to_the_other(
        format_id, "enclave_a", enclave_a, "enclave_b", enclave_b);
    if (ret)
    {
        printf("Host: attestation failed with %d\n", ret);
        goto exit;
    }

    // attest enclave B to enclave A
    ret = attest_one_enclave_to_the_other(
        format_id, "enclave_b", enclave_b, "enclave_a", enclave_a);
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

    ret = 0;

exit:
    // Free host memory allocated by the enclave.
    free(encrypted_message);

    printf("Host: Terminating enclaves\n");
    if (enclave_a)
        terminate_enclave(enclave_a);

    if (enclave_b)
        terminate_enclave(enclave_b);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
