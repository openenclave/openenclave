// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "mbedtls_utility.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/sgx/report.h>

// SGX Remote Attestation UUID.
static oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};

// Consider to move this function into a shared directory
oe_result_t generate_certificate_and_pkey(
    mbedtls_x509_crt* certificate,
    mbedtls_pk_context* private_key)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    int ret = 0;

    result = generate_key_pair(
        &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);
    if (result != OE_OK)
    {
        printf("generate_key_pair failed with %s\n", oe_result_str(result));
        goto exit;
    }

    printf("public key used:\n%s\n", public_key_buffer);

    // both ec key such ASYMMETRIC_KEY_EC_SECP256P1 or RSA key work
    oe_attester_initialize();
    result = oe_get_attestation_certificate_with_evidence(
        &_uuid_sgx_ecdsa,
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        &output_certificate,
        &output_certificate_size);
    if (result != OE_OK)
    {
        printf(
            "oe_generate_attestation_certificate failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // create mbedtls_x509_crt from output_cert
    ret = mbedtls_x509_crt_parse_der(
        certificate, output_certificate, output_certificate_size);
    if (ret != 0)
    {
        printf("mbedtls_x509_crt_parse_der failed with ret = %d\n", ret);
        result = OE_FAILURE;
        goto exit;
    }

    // create mbedtls_pk_context from private key data
    ret = mbedtls_pk_parse_key(
        private_key,
        (const unsigned char*)private_key_buffer,
        private_key_buffer_size,
        NULL,
        0);
    if (ret != 0)
    {
        printf("mbedtls_pk_parse_key failed with ret = %d\n", ret);
        result = OE_FAILURE;
        goto exit;
    }

exit:
    oe_attester_shutdown();
    oe_free_key(private_key_buffer, private_key_buffer_size, NULL, 0);
    oe_free_key(public_key_buffer, public_key_buffer_size, NULL, 0);
    oe_free_attestation_certificate(output_certificate);
    return result;
}
