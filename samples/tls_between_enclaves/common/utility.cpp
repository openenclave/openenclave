// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "utility.h"
// clang-format on

#define MAX_PUBLIC_KEY_BUFF_SIZE 2048

extern oe_result_t get_tls_cert_keys(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size);

// check whether the crt is from a trust party
bool is_certificate_public_key_trusted(
    mbedtls_x509_crt* crt,
    char* trusted_pub_key,
    int trusted_pub_key_size)
{
    bool ret = false;
    unsigned char* pub_key = NULL;

    pub_key = (unsigned char*)malloc(MAX_PUBLIC_KEY_BUFF_SIZE);
    if (pub_key == NULL)
        goto done;

    ret = mbedtls_pk_write_pubkey_pem(
        &crt->pk, (unsigned char*)pub_key, MAX_PUBLIC_KEY_BUFF_SIZE);
    if (ret != 0)
    {
        printf("mbedtls_pk_write_pubkey_pem failed with ret = %d\n", ret);
        goto done;
    }
    printf(
        "pub_key size = %zu pub_key = [%s] \n",
        strlen((const char*)pub_key),
        pub_key);

    if (strncmp(trusted_pub_key, (const char*)pub_key, trusted_pub_key_size) !=
        0)
        goto done;

    printf("The public key in received certificate is trusted\n");
    ret = true;

done:

    free(pub_key);
    return ret;
}

// Compute the sha256 hash of given data.
static int sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

// Consider to move this function into a shared directory
oe_result_t generate_tls_certificate(
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

    result = get_tls_cert_keys(
        &public_key_buf,
        &public_key_buf_size,
        &private_key_buf,
        &private_key_buf_size);

    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto exit;
    }

    printf("public key used:\n[%s]\n", public_key_buf);

    // both ec key such ASYMMETRIC_KEY_EC_SECP256P1 or RSA key work
    result = oe_generate_attestation_certificate(
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
    oe_free_attestation_certificate(output_cert);
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

    signer = (unsigned char*)malloc(signer_id_buf_size);
    if (signer == NULL)
    {
        printf("Out of memory\n");
        goto exit;
    }

    printf("Verify connecting client's identity\n");
    printf("public key buffer size[%lu]\n", sizeof(siging_public_key_buf));
    printf("public key\n[%s]\n", siging_public_key_buf);

    mbedtls_pk_init(&ctx);
    res = mbedtls_pk_parse_public_key(
        &ctx,
        (const unsigned char*)siging_public_key_buf,
        siging_public_key_buf_size);
    if (res != 0)
    {
        printf("mbedtls_pk_parse_public_key failed with %d\n", res);
        goto exit;
    }

    pk_type = mbedtls_pk_get_type(&ctx);
    if (pk_type != MBEDTLS_PK_RSA)
    {
        printf("mbedtls_pk_get_type had incorrect type: %d\n", res);
        goto exit;
    }
    printf("This public sigining key is a rsa key \n");

    rsa_ctx = mbedtls_pk_rsa(ctx);
    modulus_size = mbedtls_rsa_get_len(rsa_ctx);
    printf("modulus_size = [%zu]\n", modulus_size);
    modulus = (uint8_t*)malloc(modulus_size);
    if (modulus == NULL)
    {
        printf("malloc for modulus failed with size %zu:\n", modulus_size);
        goto exit;
    }

    res = mbedtls_rsa_export_raw(
        rsa_ctx, modulus, modulus_size, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    if (res != 0)
    {
        printf("mbedtls_rsa_export failed with %d\n", res);
        goto exit;
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
    if (sha256(modulus, modulus_size, signer) != 0)
    {
        printf("sha256 failed\n");
        goto exit;
    }

    if (memcmp(signer, signer_id_buf, signer_id_buf_size) != 0)
    {
        printf("mrsigner is not equal!\n");
        for (int i = 0; i < signer_id_buf_size; i++)
        {
            printf(
                "0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id_buf[i]);
        }
        goto exit;
    }
    ret = true;
exit:
    if (signer)
        free(signer);

    if (modulus != NULL)
        free(modulus);

    mbedtls_pk_free(&ctx);
    return ret;
}
