// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "mbedtls_utility.h"
#include "tls_e2e_t.h"

extern struct tls_control_args g_control_config;

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
        certificate_subject_name,
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

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    oe_result_t result = OE_FAILURE;
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    if (g_control_config.fail_cert_verify_callback)
    {
        OE_TRACE_INFO(
            "Purposely returns failure from server's cert_verify_callback()\n");
        goto done;
    }

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    OE_TRACE_INFO("cert_verify_callback with depth = %d\n", depth);
    OE_TRACE_INFO("crt->version = %d\n", crt->version);
    OE_TRACE_INFO("cert_size = %zu\n", cert_size);

    if (cert_size <= 0)
        goto done;

    OE_TRACE_INFO("Calling oe_verify_attestation_certificate\n");
    if (g_control_config.fail_oe_verify_attestation_certificate)
        goto done;

    result = oe_verify_attestation_certificate(
        cert_buf, cert_size, enclave_identity_verifier, NULL);
    OE_CHECK_MSG(
        result,
        "oe_verify_attestation_certificate failed with result = %s\n",
        oe_result_str(result));

    OE_TRACE_INFO("\nReturned from oe_verify_attestation_certificate\n");
    ret = 0;
    *flags = 0;
done:
    return ret;
}