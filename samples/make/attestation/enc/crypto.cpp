// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>

// Includes for mbedtls shipped with oe.
// Also add the following libraries to your linker command line:
// -loeenclave -lmbedcrypto -lmbedtls -lmbedx509
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include "log.h"

mbedtls_ctr_drbg_context g_ctr_drbg_context;
mbedtls_entropy_context g_entropy_context;

mbedtls_pk_context g_rsa_context;
uint8_t g_my_public_key[512];

bool g_initialized = false;

/**
 * mbedtls cleanup during shutdown.
 */
static void CleanupMbedtls(void)
{
    mbedtls_pk_free(&g_rsa_context);
    mbedtls_entropy_free(&g_entropy_context);
    mbedtls_ctr_drbg_free(&g_ctr_drbg_context);
    ENC_DEBUG_PRINTF("mbedtls cleaned up.");
}

/**
 * mbedtls initialization. Please refer to mbedtls documentation for detailed
 * information about the functions used.
 */
static void InitializeMbedtls(void)
{
    int res = -1;

    mbedtls_ctr_drbg_init(&g_ctr_drbg_context);
    mbedtls_entropy_init(&g_entropy_context);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &g_ctr_drbg_context, mbedtls_entropy_func, &g_entropy_context, NULL, 0);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_ctr_drbg_seed failed.");
        return;
    }

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &g_rsa_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_setup failed.");
        return;
    }

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(g_rsa_context),
        mbedtls_ctr_drbg_random,
        &g_ctr_drbg_context,
        2048,
        65537);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_gen_key failed.");
        return;
    }

    // Write out the public key in PEM format for exchange with other enclaves.
    res = mbedtls_pk_write_pubkey_pem(
        &g_rsa_context, g_my_public_key, sizeof(g_my_public_key));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_write_pubkey_pem failed.");
        return;
    }

    // Schedule cleanup.
    atexit(CleanupMbedtls);

    g_initialized = true;
    ENC_DEBUG_PRINTF("mbedtls initialized.");
}

/** InitializeCrypto initializes the crypto module.
 *  Uses oe_once to ensure that InitializeMbedtls is called only once.
 */
bool InitializeCrypto(void)
{
    InitializeMbedtls();
    return g_initialized;
}

/**
 * Get the public key for this enclave.
 */
void GetPublicKey(uint8_t pem_public_key[512])
{
    memcpy(pem_public_key, g_my_public_key, sizeof(g_my_public_key));
}

/**
 * Compute the sha256 hash of given data.
 */
void Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, data, data_size);
    mbedtls_sha256_finish_ret(&ctx, sha256);
}

/**
 * Encrypt encrypts the given data using the given public key.
 * Used to encrypt data using the public key of another enclave.
*/
bool Encrypt(
    const uint8_t* pem_public_key,
    const uint8_t* data,
    size_t data_size,
    uint8_t* encrypted_data,
    size_t* encrypted_data_size)
{
    bool result = false;
    mbedtls_pk_context key;
    size_t key_size = 0;
    int res = -1;

    mbedtls_pk_init(&key);

    if (!g_initialized)
        goto done;

    // Read the given public key.
    key_size = strlen((const char*)pem_public_key) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_parse_public_key failed.");
        goto done;
    }

    // Encrypt the data.
    res = mbedtls_rsa_pkcs1_encrypt(
        mbedtls_pk_rsa(key),
        mbedtls_ctr_drbg_random,
        &g_ctr_drbg_context,
        MBEDTLS_RSA_PUBLIC,
        data_size,
        data,
        encrypted_data);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_encrypt failed.");
        goto done;
    }

    *encrypted_data_size = mbedtls_pk_rsa(key)->len;

    result = true;
done:
    mbedtls_pk_free(&key);
    return result;
}

/**
 * Decrypt decrypts the given data using current enclave's private key.
 * Used to receive encrypted data from another enclave.
 */
bool Decrypt(
    const uint8_t* encrypted_data,
    size_t encrypted_data_size,
    uint8_t* data,
    size_t* data_size)
{
    if (!g_initialized)
        return false;

    mbedtls_pk_rsa(g_rsa_context)->len = encrypted_data_size;

    size_t output_size = *data_size;
    int res = mbedtls_rsa_pkcs1_decrypt(
        mbedtls_pk_rsa(g_rsa_context),
        mbedtls_ctr_drbg_random,
        &g_ctr_drbg_context,
        MBEDTLS_RSA_PRIVATE,
        &output_size,
        encrypted_data,
        data,
        output_size);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_decrypt failed.");
        return false;
    }
    *data_size = output_size;
    return true;
}
