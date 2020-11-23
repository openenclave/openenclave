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
    mbedtls_x509_crt* cert,
    mbedtls_pk_context* private_key)
{
    oe_result_t result = OE_FAILURE;
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

    printf("public key used:\n%s\n", public_key_buf);

    // both ec key such ASYMMETRIC_KEY_EC_SECP256P1 or RSA key work
    oe_attester_initialize();
    result = oe_get_attestation_certificate_with_evidence(
        &_uuid_sgx_ecdsa,
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
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
    oe_attester_shutdown();
    oe_free_key(private_key_buf, private_key_buf_size, NULL, 0);
    oe_free_key(public_key_buf, public_key_buf_size, NULL, 0);
    oe_free_attestation_certificate(output_cert);
    return result;
}