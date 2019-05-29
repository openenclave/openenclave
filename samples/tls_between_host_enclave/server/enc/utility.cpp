// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <stdio.h>
#include "utility.h"
// clang-format on

// input: input_data and input_data_len
// output: key, key_size
oe_result_t generate_key_pair(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size)
{
    oe_result_t result = OE_FAILURE;
    oe_asymmetric_key_params_t params;
    char user_data[] = "test user data!";
    size_t user_data_size = sizeof(user_data) - 1;

    // Call oe_get_public_key_by_policy() to generate key pair derived from an
    // enclave's seal key If an enclave does not want to have this key pair tied
    // to enclave instance, it can generate its own key pair using any chosen
    // crypto API

    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1; // MBEDTLS_ECP_DP_SECP256R1
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = user_data;
    params.user_data_size = user_data_size;
    result = oe_get_public_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        public_key,
        public_key_size,
        NULL,
        NULL);
    if (result != OE_OK)
    {
        printf(
            "oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
            oe_result_str(result));
        goto done;
    }

    result = oe_get_private_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        private_key,
        private_key_size,
        NULL,
        NULL);
    if (result != OE_OK)
    {
        printf(
            "oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
            oe_result_str(result));
        goto done;
    }

done:
    return result;
}

// Consider to move this function into a shared directory
oe_result_t generate_certificate_and_pkey(
    mbedtls_x509_crt* cert,
    mbedtls_pk_context* private_key)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* host_cert_buf = NULL;
    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;
    uint8_t* private_key_buf = NULL;
    size_t private_key_buf_size = 0;
    uint8_t* public_key_buf = NULL;
    size_t public_key_buf_size = 0;
    int ret = 0;

    result = generate_key_pair(
        &public_key_buf,
        &public_key_buf_size,
        &private_key_buf,
        &private_key_buf_size);
    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto exit;
    }

    printf("\n\npublic_key_buf_size:[%ld]\n", public_key_buf_size);
    printf("public key used:\n[%s]\n\n", public_key_buf);

    result = oe_gen_tls_cert(
        private_key_buf,
        private_key_buf_size,
        public_key_buf,
        public_key_buf_size,
        &output_cert,
        &output_cert_size);
    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto exit;
    }

    // create mbedtls_x509_crt from output_cert
    ret = mbedtls_x509_crt_parse_der(cert, output_cert, output_cert_size);
    if (ret != 0)
    {
        printf(" failed with ret = %d\n", ret);
        result = OE_FAILURE;
        goto exit;
    }

    // create mbedtls_pk_context from private key data
    ret = mbedtls_pk_parse_key(
        private_key,
        (const unsigned char*)private_key_buf,
        private_key_buf_size,
        NULL,
        0);
    if (ret != 0)
    {
        printf(" failed with ret = %d\n", ret);
        result = OE_FAILURE;
        goto exit;
    }

exit:
    oe_free_key(private_key_buf, private_key_buf_size, NULL, 0);
    oe_free_key(public_key_buf, public_key_buf_size, NULL, 0);
    oe_free_tls_cert(output_cert);
    return result;
}
