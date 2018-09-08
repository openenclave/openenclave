// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crypto.h"
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>

Crypto::Crypto()
{
    m_Initialized = InitializeMbedtls();
}

Crypto::~Crypto()
{
    CleanupMbedtls();
}

/**
 * InitializeMbedtls initializes the crypto module.
 * mbedtls initialization. Please refer to mbedtls documentation for detailed
 * information about the functions used.
 */
bool Crypto::InitializeMbedtls(void)
{
    bool ret = false;
    int res = -1;

    mbedtls_ctr_drbg_init(&m_CtrDrbgContext);
    mbedtls_entropy_init(&m_EntropyContext);
    mbedtls_pk_init(&m_RsaContext);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &m_CtrDrbgContext, mbedtls_entropy_func, &m_EntropyContext, NULL, 0);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_ctr_drbg_seed failed.");
        goto exit;
    }

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &m_RsaContext, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_setup failed (%d).", res);
        goto exit;
    }

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_RsaContext),
        mbedtls_ctr_drbg_random,
        &m_CtrDrbgContext,
        2048,
        65537);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_gen_key failed (%d)\n", res);
        goto exit;
    }

    // Write out the public key in PEM format for exchange with other enclaves.
    res = mbedtls_pk_write_pubkey_pem(
        &m_RsaContext, m_MyPublicKey, sizeof(m_MyPublicKey));
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pk_write_pubkey_pem failed (%d)\n", res);
        goto exit;
    }
    ret = true;
    ENC_DEBUG_PRINTF("mbedtls initialized.");
exit:
    return ret;
}

/**
 * mbedtls cleanup during shutdown.
 */
void Crypto::CleanupMbedtls(void)
{
    mbedtls_pk_free(&m_RsaContext);
    mbedtls_entropy_free(&m_EntropyContext);
    mbedtls_ctr_drbg_free(&m_CtrDrbgContext);

    ENC_DEBUG_PRINTF("mbedtls cleaned up.");
}

/**
 * Get the public key for this enclave.
 */
void Crypto::RetrievePublicKey(uint8_t pemPublicKey[512])
{
    memcpy(pemPublicKey, m_MyPublicKey, sizeof(m_MyPublicKey));
}

/**
 * Compute the sha256 hash of given data.
 */
void Crypto::Sha256(const uint8_t* data, size_t dataSize, uint8_t sha256[32])
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
bool Crypto::Encrypt(
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

    if (!m_Initialized)
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
        &m_CtrDrbgContext,
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
bool Crypto::Decrypt(
    const uint8_t* encryptedData,
    size_t encryptedDataSize,
    uint8_t* data,
    size_t* dataSize)
{
    bool ret = false;
    size_t outputSize = 0;
    int res = 0;

    if (!m_Initialized)
        goto exit;

    mbedtls_pk_rsa(m_RsaContext)->len = encryptedDataSize;

    outputSize = *dataSize;
    res = mbedtls_rsa_pkcs1_decrypt(
        mbedtls_pk_rsa(m_RsaContext),
        mbedtls_ctr_drbg_random,
        &m_CtrDrbgContext,
        MBEDTLS_RSA_PRIVATE,
        &outputSize,
        encryptedData,
        data,
        outputSize);
    if (res != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_rsa_pkcs1_decrypt failed.");
        goto exit;
    }
    *dataSize = outputSize;
    ret = true;

exit:
    return ret;
}
