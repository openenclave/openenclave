// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_e2e_t.h"
#include "utility.h"
// clang-format on

extern struct tls_control_args g_control_config;

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

// Compute the sha256 hash of given data.
static int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto done;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto done;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto done;

done:
    mbedtls_sha256_free(&ctx);
    return ret;
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

    result = oe_gen_tls_cert(
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
    oe_free_tls_cert(output_cert);

    return result;
}

bool verify_mrsigner(
    char* siging_public_key_buf,
    size_t siging_public_key_buf_size,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size)
{
    mbedtls_pk_context ctx;
    mbedtls_pk_type_t pk_type;
    mbedtls_rsa_context* rsa_ctx = NULL;
    uint8_t* modulus = NULL;
    size_t modulus_size = 0;
    int res = 0;
    bool ret = false;
    unsigned char* signer = NULL;

    signer = (unsigned char*)oe_malloc(signer_id_buf_size);
    if (signer == NULL)
    {
        OE_TRACE_ERROR("Out of memory\n");
        goto done;
    }

    OE_TRACE_INFO("Verify connecting client's identity\n");
    OE_TRACE_INFO(
        "public key buffer size[%lu]\n", sizeof(siging_public_key_buf));
    OE_TRACE_INFO("public key\n[%s]\n", siging_public_key_buf);

    mbedtls_pk_init(&ctx);
    res = mbedtls_pk_parse_public_key(
        &ctx,
        (const unsigned char*)siging_public_key_buf,
        siging_public_key_buf_size);
    if (res != 0)
    {
        OE_TRACE_ERROR("mbedtls_pk_parse_public_key failed with %d\n", res);
        goto done;
    }
    OE_TRACE_INFO(
        "siging_public_key_buf_size=%ld\n", siging_public_key_buf_size);

    pk_type = mbedtls_pk_get_type(&ctx);
    if (pk_type != MBEDTLS_PK_RSA)
    {
        OE_TRACE_ERROR("mbedtls_pk_get_type had incorrect type: %d\n", res);
        goto done;
    }
    OE_TRACE_INFO("This public sigining key is a rsa key \n");

    rsa_ctx = mbedtls_pk_rsa(ctx);
    modulus_size = mbedtls_rsa_get_len(rsa_ctx);
    OE_TRACE_INFO("modulus_size = [%zu]\n", modulus_size);
    modulus = (uint8_t*)oe_malloc(modulus_size);
    if (modulus == NULL)
    {
        OE_TRACE_ERROR(
            "malloc for modulus failed with size %zu:\n", modulus_size);
        goto done;
    }

    res = mbedtls_rsa_export_raw(
        rsa_ctx, modulus, modulus_size, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    if (res != 0)
    {
        OE_TRACE_ERROR("mbedtls_rsa_export failed with %d\n", res);
        goto done;
    }

    // Reverse the modulus and compute sha256 on it.
    for (size_t i = 0; i < modulus_size / 2; i++)
    {
        uint8_t tmp = modulus[i];
        modulus[i] = modulus[modulus_size - 1 - i];
        modulus[modulus_size - 1 - i] = tmp;
    }

    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus. This value
    // is populated by the signer_id sub-field of a parsed oe_report_t's
    // identity field.

    OE_TRACE_ERROR("modulus_size=%ld\n", modulus_size);
    if (Sha256(modulus, modulus_size, signer) != 0)
    {
        OE_TRACE_ERROR("Sha256 failed\n");
        goto done;
    }

    if (memcmp(signer, signer_id_buf, signer_id_buf_size) != 0)
    {
        OE_TRACE_ERROR("mrsigner is not equal!\n");
        for (size_t i = 0; i < signer_id_buf_size; i++)
        {
            OE_TRACE_ERROR(
                "0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id_buf[i]);
        }
        goto done;
    }
    ret = true;
done:
    if (signer)
        oe_free(signer);

    if (modulus != NULL)
        oe_free(modulus);

    mbedtls_pk_free(&ctx);
    return ret;
}

// If set, the verify callback is called for each certificate in the chain.
// The verification callback is supposed to return 0 on success. Otherwise, the
// verification failed.
// The function should return 0 for anything (including invalid
// certificates) other than fatal error, as a non-zero return
// code immediately aborts the verification process.
// For fatal errors, a specific error code should be used
// (different from MBEDTLS_ERR_X509_CERT_VERIFY_FAILED which
// should not be returned at this point), or MBEDTLS_ERR_X509_FATAL_ERROR
// can be used if no better code is available.
//
int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
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

    OE_TRACE_INFO("Calling oe_verify_tls_cert\n");
    if (g_control_config.fail_oe_verify_tls_cert)
        goto done;

    result = oe_verify_tls_cert(
        cert_buf, cert_size, enclave_identity_verifier, NULL);
    OE_CHECK_MSG(
        result,
        "oe_verify_tls_cert failed with result = %s\n",
        oe_result_str(result));

    OE_TRACE_INFO("\nReturned from oe_verify_tls_cert\n");
    ret = 0;
    *flags = 0;
done:
    return ret;
}
