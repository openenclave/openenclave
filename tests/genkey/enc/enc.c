// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>

#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include "genkey_t.h"

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
    // enclave's seal key. If an enclave does not want to have this key pair
    // tied to enclave instance, it can generate its own key pair using any
    // chosen crypto API

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
    OE_CHECK_MSG(
        result,
        "oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
        oe_result_str(result));

    result = oe_get_private_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        private_key,
        private_key_size,
        NULL,
        NULL);
    OE_CHECK_MSG(
        result,
        "oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
        oe_result_str(result));

done:
    return result;
}

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
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

#if 0
    OE_TRACE_INFO("private_key_buf_size:[%ld]\n", private_key_buf_size);
#endif

    OE_TRACE_INFO("public_key_buf_size:[%ld]\n", public_key_buf_size);
    OE_TRACE_INFO("public key used:\n[%s]", public_key_buf);

    result = oe_generate_attestation_certificate(
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key_buf,
        private_key_buf_size,
        public_key_buf,
        public_key_buf_size,
        &output_cert,
        &output_cert_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    // create mbedtls_x509_crt from output_cert
    ret = mbedtls_x509_crt_parse_der(cert, output_cert, output_cert_size);
    if (ret != 0)
        OE_RAISE_MSG(OE_VERIFY_FAILED, " failed with ret = %d\n", ret);

    // create mbedtls_pk_context from private key data
    ret = mbedtls_pk_parse_key(
        private_key,
        (const unsigned char*)private_key_buf,
        private_key_buf_size,
        NULL,
        0);
    if (ret != 0)
        OE_RAISE_MSG(OE_VERIFY_FAILED, " failed with ret = %d\n", ret);

done:
    oe_free_key(private_key_buf, private_key_buf_size, NULL, 0);
    oe_free_key(public_key_buf, public_key_buf_size, NULL, 0);
    oe_free_attestation_certificate(output_cert);

    return result;
}

int genkey_ecall(void)
{
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context private_key;

    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&private_key);

    generate_certificate_and_pkey(&client_cert, &private_key);

    mbedtls_x509_crt_free(&client_cert);
    mbedtls_pk_free(&private_key);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
