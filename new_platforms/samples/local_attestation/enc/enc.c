// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include "localattestation_t.h"
#include <string.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/sha256.h>

mbedtls_x509_crt other_enclave_cert;

int oe_random_wrapper(void* param, unsigned char* buffer, size_t len)
{
    return oe_random(buffer, len);
}

// Attest and store the certificate of another enclave.
int verify_report_and_store_certificate(
    uint8_t* local_report,
    size_t report_size)
{
    oe_report_t parsed_report;
    oe_result_t result = oe_verify_report(local_report, report_size, &parsed_report);
    if (result != OE_OK)
    {
        goto exit;
    }

    mbedtls_x509_crt_init(&other_enclave_cert);
    int ret = mbedtls_x509_crt_parse(&other_enclave_cert, local_report, report_size);
    if (ret != 0)
    {
        result = OE_FAILURE;
        goto exit;
    }

    printf("verify_report_and_store_certificate succeeded.\n");

exit:
    return result;
}

static int mbedtls_sha256_hash(
    unsigned char* output,
    const unsigned char* input,
    const size_t input_size)
{
    int ret = 0;
    mbedtls_sha256_context sha256;

    mbedtls_sha256_init(&sha256);

    mbedtls_sha256_update(&sha256, input, input_size);

    mbedtls_sha256_finish(&sha256, output);

    mbedtls_sha256_free(&sha256);

    return ret;
}

// Sign message for another enclave
int generate_signed_message(
    uint8_t* data, 
    size_t data_size, 
    size_t* data_size_needed, 
    uint8_t* signature,
    size_t signature_size,
    size_t* signature_size_needed)
{
    uint8_t data_buf[] = "foobar";
    mbedtls_pk_context key_ctx = {0};
    uint8_t* key_buf = NULL;
    size_t key_buf_size;

    *data_size_needed = sizeof(data_buf);
    if (data_size < *data_size_needed)
    {
        return OE_BUFFER_TOO_SMALL;
    }

    memcpy(data, data_buf, *data_size_needed);

    oe_asymmetric_key_params_t key_params;
    key_params.format = OE_ASYMMETRIC_KEY_PEM;
    key_params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    key_params.user_data = NULL;
    key_params.user_data_size = 0;
    oe_result_t result =
        oe_get_private_key(&key_params, NULL, 0, &key_buf, &key_buf_size);
    if (result != OE_OK)
    {
        goto exit;
    }

    int ret = mbedtls_pk_parse_key(&key_ctx, key_buf, key_buf_size, NULL, 0);
    if (ret != 0)
    {
        result = OE_FAILURE;
        goto exit;
    }

    {
        uint8_t hash[32];
        mbedtls_sha256_hash(hash, data_buf, *data_size_needed);

        *signature_size_needed = signature_size;
        ret = mbedtls_pk_sign(
            &key_ctx,
            MBEDTLS_MD_SHA256,
            hash, 
            sizeof(hash), 
            signature, 
            signature_size_needed,
            oe_random_wrapper, 
            NULL);
        if (ret != 0)
        {
            result = OE_FAILURE;
            goto exit;
        }

        if (signature_size < *signature_size_needed)
        {
            result = OE_FAILURE;
            goto exit;
        }
    }

    printf("Successfully signed message\n");

exit: 
    if (key_buf)
    {
        oe_free_key(key_buf, key_buf_size, NULL, 0);
    }

    return result;
}

// Process signed message
int process_signed_msg(
    uint8_t* data, 
    size_t data_size, 
    uint8_t* signature, 
    size_t signature_size)
{
    oe_result_t result = OE_OK;

    uint8_t hash[32];
    mbedtls_sha256_hash(hash, data, data_size);

    int ret = mbedtls_pk_verify(
        &other_enclave_cert.pk, 
        MBEDTLS_MD_SHA256,
        hash,
        sizeof(hash),
        signature,
        signature_size);
    if (ret)
    {
        result = OE_FAILURE;
        goto exit;
    }

    printf(
        "Successfully received and verified signed message %s\n",
        data);

exit:
    return result;
}
