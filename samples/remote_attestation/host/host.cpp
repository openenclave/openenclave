// Copyright (c) Open Enclave SDK contributors.
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
    uint8_t* encrypted_message = NULL;
    size_t encrypted_message_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;

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

    printf("Host: requesting a remote evidence and the encryption key from 1st "
           "enclave\n");
    result = get_remote_evidence_with_public_key(
        enclave_a, &ret, &pem_key, &pem_key_size, &evidence, &evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: 1st enclave's public key: \n%s", pem_key);

    printf("Host: requesting 2nd enclave to attest 1st enclave's the remote "
           "evidence and the public key\n");
    result = verify_evidence_and_set_public_key(
        enclave_b, &ret, pem_key, pem_key_size, evidence, evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(evidence);
    evidence = NULL;

    printf("Host: Requesting a remote evidence and the encryption key from "
           "2nd enclave=====\n");
    result = get_remote_evidence_with_public_key(
        enclave_b, &ret, &pem_key, &pem_key_size, &evidence, &evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: 2nd enclave's public key: \n%s", pem_key);

    printf("Host: Requesting first enclave to attest 2nd enclave's "
           "remote evidence and the public key=====\n");
    result = verify_evidence_and_set_public_key(
        enclave_a, &ret, pem_key, pem_key_size, evidence, evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    free(pem_key);
    pem_key = NULL;
    free(evidence);
    evidence = NULL;

    printf("Host: Remote attestation Succeeded\n");

    // Free host memory allocated by the enclave.
    free(encrypted_message);
    encrypted_message = NULL;
    ret = 0;

exit:
    if (pem_key)
        free(pem_key);

    if (evidence)
        free(evidence);

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
