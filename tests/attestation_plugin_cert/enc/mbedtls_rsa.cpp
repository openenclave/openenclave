// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <openenclave/internal/raise.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

oe_result_t generate_rsa_pair(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* local_public_key = nullptr;
    uint8_t* local_private_key = nullptr;
    int res = -1;
    mbedtls_ctr_drbg_context ctr_drbg_contex;
    mbedtls_entropy_context entropy_context;
    mbedtls_pk_context pk_context;

    mbedtls_ctr_drbg_init(&ctr_drbg_contex);
    mbedtls_entropy_init(&entropy_context);
    mbedtls_pk_init(&pk_context);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &ctr_drbg_contex, mbedtls_entropy_func, &entropy_context, nullptr, 0);
    if (res != 0)
        OE_RAISE_MSG(OE_FAILURE, "mbedtls_ctr_drbg_seed failed.");

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
        OE_RAISE_MSG(OE_FAILURE, "mbedtls_pk_setup failed (%d).", res);

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(pk_context),
        mbedtls_ctr_drbg_random,
        &ctr_drbg_contex,
        2048,
        65537);
    if (res != 0)
        OE_RAISE_MSG(OE_FAILURE, "mbedtls_rsa_gen_key failed (%d)\n", res);

    /* Call again with the allocated memory. */
    local_public_key = (uint8_t*)calloc(1, OE_RSA_PUBLIC_KEY_SIZE);
    if (local_public_key == nullptr)
        OE_RAISE(OE_OUT_OF_MEMORY);

    local_private_key = (uint8_t*)calloc(1, OE_RSA_PRIVATE_KEY_SIZE);
    if (local_private_key == nullptr)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Write out the public/private key in PEM format for exchange with
    // other enclaves.
    res = mbedtls_pk_write_pubkey_pem(
        &pk_context, local_public_key, OE_RSA_PUBLIC_KEY_SIZE);
    if (res != 0)
        OE_RAISE_MSG(
            OE_FAILURE, "mbedtls_pk_write_pubkey_pem failed (%d)\n", res);

    res = mbedtls_pk_write_key_pem(
        &pk_context, local_private_key, OE_RSA_PRIVATE_KEY_SIZE);
    if (res != 0)
        OE_RAISE_MSG(OE_FAILURE, "mbedtls_pk_write_key_pem failed (%d)\n", res);

    *public_key = local_public_key;
    // plus one to make sure \0 at the end is counted
    *public_key_size = strlen((const char*)local_public_key) + 1;

    *private_key = local_private_key;
    *private_key_size = strlen((const char*)local_private_key) + 1;

    local_public_key = nullptr;
    local_private_key = nullptr;

    OE_TRACE_INFO("public_key_size\n[%d]\n", *public_key_size);
    OE_TRACE_INFO("public_key\n[%s]\n", *public_key);
    result = OE_OK;

done:
    if (local_public_key)
        free(local_public_key);
    if (local_private_key)
        free(local_private_key);
    mbedtls_pk_free(&pk_context);
    mbedtls_ctr_drbg_free(&ctr_drbg_contex);
    mbedtls_entropy_free(&entropy_context);

    return result;
}
