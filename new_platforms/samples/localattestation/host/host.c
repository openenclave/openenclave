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
        OE_ENCLAVE_TYPE_TRUSTZONE,
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

    result = oe_get_report_v2(enclave_b, 0, NULL, 0, &report, &report_size);
    if (result != OE_OK)
    {
        ret = 1;
        goto exit;
    }

    printf("Host: verify_report_and_store_certificate in %s\n", enclave_a_name);
    result = verify_report_and_store_certificate(
        enclave_a, &ret, report, report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_report_and_store_certificate failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

exit:
    if (report)
        oe_free_report(report);
    return ret;
}

#define TA_UUID "97d140f4-5f59-4d1f-9735-cb21d49e7eb7"

#ifdef OE_USE_SGX
int main(int argc, const char* argv[])
{
    printf("This sample is designed for CyReS TAs only (currently "
           "OP TEE)\n");
    return 0;
}
#endif

#ifdef OE_USE_OPTEE
int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave1 = NULL;
    oe_enclave_t* enclave2 = NULL;
    uint8_t msg[1024];
    size_t msg_size = 0, signature_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;

    printf("Host: Creating two enclaves\n");
    enclave1 = create_enclave(TA_UUID);
    if (enclave1 == NULL)
    {
        goto exit;
    }
    enclave2 = create_enclave(TA_UUID);
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

    printf(
        "\n***\nHost: Now both enclaves have attested each other.\n"
        "They can start exchanging signed messages between them \n"
        "using the public keys exchanged earlier\n"
        "***\n\n");

    // With successfully attestation on each other, we are ready to exchange
    // data between enclaves
    printf("Host: Requesting signed message from 1st enclave\n");
    uint8_t signature[72];
    result = generate_signed_message(
        enclave1, 
        &ret, 
        msg, 
        sizeof(msg), 
        &msg_size, 
        signature, 
        sizeof(signature),
        &signature_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_signed_message failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: Sending the signed message to 2nd enclave\n");
    result = process_signed_msg(
        enclave2, &ret, msg, msg_size, signature, signature_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Host: process_signed_msg failed. %s\n", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Host: Requesting signed message from 2nd enclave\n");
    result = generate_signed_message(
        enclave2, 
        &ret, 
        msg, 
        sizeof(msg), 
        &msg_size, 
        signature, 
        sizeof(signature),
        &signature_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: generate_signed_message failed. %s",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    printf("Sending signed message to 1st  enclave=====\n");
    result = process_signed_msg(
        enclave1, &ret, msg, msg_size, signature, signature_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("host process_signed_msg failed. %s", oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    printf("Host: Success\n");

    ret = 0;
exit:

    printf("Host: Terminating enclaves\n");
    if (enclave1)
        terminate_enclave(enclave1);

    if (enclave2)
        terminate_enclave(enclave2);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
#endif
