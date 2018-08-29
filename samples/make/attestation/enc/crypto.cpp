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

mbedtls_ctr_drbg_context g_CtrDrbgContext;
mbedtls_entropy_context g_EntropyContext;

mbedtls_pk_context g_RsaContext;
uint8_t g_MyPublicKey[512];

bool g_Initialized = false;

/**
 * mbedtls cleanup during shutdown.
 */
static void CleanupMbedtls(void)
{
    mbedtls_pk_free(&g_RsaContext);
    mbedtls_entropy_free(&g_EntropyContext);
    mbedtls_ctr_drbg_free(&g_CtrDrbgContext);
    ENC_DEBUG_PRINTF("mbedtls cleaned up.");
}

/**
 * mbedtls initialization. Please refer to mbedtls documentation for detailed
 * information about the functions used.
 */
static void InitializeMbedtls(void)
{
    int res = -1;

    mbedtls_ctr_drbg_init(&g_CtrDrbgContext);
    mbedtls_entropy_init(&g_EntropyContext);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &g_CtrDrbgContext, mbedtls_entropy_func, &g_EntropyContext, NULL, 0);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_ctr_drbg_seed failed.");
        return;
    }

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &g_RsaContext, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_setup failed.");
        return;
    }

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(g_RsaContext),
        mbedtls_ctr_drbg_random,
        &g_CtrDrbgContext,
        2048,
        65537);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_gen_key failed.");
        return;
    }

    // Write out the public key in PEM format for exchange with other enclaves.
    res = mbedtls_pk_write_pubkey_pem(
        &g_RsaContext, g_MyPublicKey, sizeof(g_MyPublicKey));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_write_pubkey_pem failed.");
        return;
    }

    // Schedule cleanup.
    atexit(CleanupMbedtls);

    g_Initialized = true;
    ENC_DEBUG_PRINTF("mbedtls initialized.");
}

/** InitializeCrypto initializes the crypto module.
 *  Uses oe_once to ensure that InitializeMbedtls is called only once.
 */
bool InitializeCrypto(void)
{
    InitializeMbedtls();
    return g_Initialized;
}

/**
 * Get the public key for this enclave.
 */
void GetPublicKey(uint8_t pemPublicKey[512])
{
    memcpy(pemPublicKey, g_MyPublicKey, sizeof(g_MyPublicKey));
}

/**
 * Compute the sha256 hash of given data.
 */
void Sha256(const uint8_t* data, size_t dataSize, uint8_t sha256[32])
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, dataSize);
    mbedtls_sha256_finish(&ctx, sha256);
}

/**
 * Encrypt encrypts the given data using the given public key.
 * Used to encrypt data using the public key of another enclave.
*/
bool Encrypt(
    const uint8_t* pemPublicKey,
    const uint8_t* data,
    size_t dataSize,
    uint8_t* encryptedData,
    size_t* encryptedDataSize)
{
    bool result = false;
    mbedtls_pk_context key;
    size_t keySize = 0;
    int res = -1;

    mbedtls_pk_init(&key);

    if (!g_Initialized)
        goto done;

    // Read the given public key.
    keySize = strlen((const char*)pemPublicKey) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pemPublicKey, keySize);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_parse_public_key failed.");
        goto done;
    }

    // Encrypt the data.
    res = mbedtls_rsa_pkcs1_encrypt(
        mbedtls_pk_rsa(key),
        mbedtls_ctr_drbg_random,
        &g_CtrDrbgContext,
        MBEDTLS_RSA_PUBLIC,
        dataSize,
        data,
        encryptedData);

    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_encrypt failed.");
        goto done;
    }

    *encryptedDataSize = mbedtls_pk_rsa(key)->len;

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
    const uint8_t* encryptedData,
    size_t encryptedDataSize,
    uint8_t* data,
    size_t* dataSize)
{
    if (!g_Initialized)
        return false;

    mbedtls_pk_rsa(g_RsaContext)->len = encryptedDataSize;

    size_t outputSize = *dataSize;
    int res = mbedtls_rsa_pkcs1_decrypt(
        mbedtls_pk_rsa(g_RsaContext),
        mbedtls_ctr_drbg_random,
        &g_CtrDrbgContext,
        MBEDTLS_RSA_PRIVATE,
        &outputSize,
        encryptedData,
        data,
        outputSize);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_decrypt failed.");
        return false;
    }
    *dataSize = outputSize;
    return true;
}
