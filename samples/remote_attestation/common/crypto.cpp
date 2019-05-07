// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crypto.h"
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Crypto::Crypto()
{
    m_initialized = init_mbedtls();
}

Crypto::~Crypto()
{
    cleanup_mbedtls();
}

/**
 * init_mbedtls initializes the crypto module.
 * mbedtls initialization. Please refer to mbedtls documentation for detailed
 * information about the functions used.
 */
bool Crypto::init_mbedtls(void)
{
    bool ret = false;
    int res = -1;

    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_pk_context);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_contex, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_seed failed.");
        goto exit;
    }

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_setup failed (%d).", res);
        goto exit;
    }

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_pk_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        2048,
        65537);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_gen_key failed (%d)\n", res);
        goto exit;
    }

    // Write out the public key in PEM format for exchange with other enclaves.
    res = mbedtls_pk_write_pubkey_pem(
        &m_pk_context, m_public_key, sizeof(m_public_key));
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_write_pubkey_pem failed (%d)\n", res);
        goto exit;
    }
    ret = true;
    TRACE_ENCLAVE("mbedtls initialized.");
exit:
    return ret;
}

/**
 * mbedtls cleanup during shutdown.
 */
void Crypto::cleanup_mbedtls(void)
{
    mbedtls_pk_free(&m_pk_context);
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);

    TRACE_ENCLAVE("mbedtls cleaned up.");
}

/**
 * Get the public key for this enclave.
 */
void Crypto::retrieve_public_key(uint8_t pem_public_key[512])
{
    memcpy(pem_public_key, m_public_key, sizeof(m_public_key));
}

// Compute the sha256 hash of given data.
int Crypto::sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
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

/**
 * Encrypt encrypts the given data using the given public key.
 * Used to encrypt data using the public key of another enclave.
 */
bool Crypto::encrypt(
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
    mbedtls_rsa_context* rsa_context;

    mbedtls_pk_init(&key);

    if (!m_initialized)
        goto exit;

    // Read the given public key.
    key_size = strlen((const char*)pem_public_key) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_parse_public_key failed.");
        goto exit;
    }

    rsa_context = mbedtls_pk_rsa(key);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    TRACE_ENCLAVE("Padding used: MBEDTLS_RSA_PKCS_V21 for OAEP or PSS");

    // Encrypt the data.
    res = mbedtls_rsa_pkcs1_encrypt(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        MBEDTLS_RSA_PUBLIC,
        data_size,
        data,
        encrypted_data);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_pkcs1_encrypt failed with %d\n", res);
        goto exit;
    }

    *encrypted_data_size = mbedtls_pk_rsa(key)->len;
    result = true;
exit:
    mbedtls_pk_free(&key);
    return result;
}

/**
 * decrypt the given data using current enclave's private key.
 * Used to receive encrypted data from another enclave.
 */
bool Crypto::decrypt(
    const uint8_t* encrypted_data,
    size_t encrypted_data_size,
    uint8_t* data,
    size_t* data_size)
{
    bool ret = false;
    size_t output_size = 0;
    int res = 0;
    mbedtls_rsa_context* rsa_context;

    if (!m_initialized)
        goto exit;

    mbedtls_pk_rsa(m_pk_context)->len = encrypted_data_size;
    rsa_context = mbedtls_pk_rsa(m_pk_context);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    output_size = *data_size;
    res = mbedtls_rsa_pkcs1_decrypt(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        MBEDTLS_RSA_PRIVATE,
        &output_size,
        encrypted_data,
        data,
        output_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_pkcs1_decrypt failed with %d\n", res);
        goto exit;
    }
    *data_size = output_size;
    ret = true;

exit:
    return ret;
}

bool Crypto::get_rsa_modulus_from_pem(
    const char* pem_data,
    size_t pem_size,
    uint8_t** modulus,
    size_t* modulus_size)
{
    mbedtls_pk_context ctx;
    mbedtls_pk_type_t pk_type;
    mbedtls_rsa_context* rsa_ctx = NULL;
    uint8_t* modulus_local = NULL;
    size_t modulus_local_size = 0;
    int res = 0;
    bool ret = false;

    if (!m_initialized || !modulus || !modulus_size)
        goto exit_preinit;

    mbedtls_pk_init(&ctx);
    res = mbedtls_pk_parse_public_key(
        &ctx, (const unsigned char*)pem_data, pem_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_parse_public_key failed with %d\n", res);
        goto exit;
    }

    pk_type = mbedtls_pk_get_type(&ctx);
    if (pk_type != MBEDTLS_PK_RSA)
    {
        TRACE_ENCLAVE("mbedtls_pk_get_type had incorrect type: %d\n", res);
        goto exit;
    }

    rsa_ctx = mbedtls_pk_rsa(ctx);
    modulus_local_size = mbedtls_rsa_get_len(rsa_ctx);
    modulus_local = (uint8_t*)malloc(modulus_local_size);
    if (modulus_local == NULL)
    {
        TRACE_ENCLAVE(
            "malloc for modulus failed with size %zu:\n", modulus_local_size);
        goto exit;
    }

    res = mbedtls_rsa_export_raw(
        rsa_ctx,
        modulus_local,
        modulus_local_size,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_export failed with %d\n", res);
        goto exit;
    }

    *modulus = modulus_local;
    *modulus_size = modulus_local_size;
    modulus_local = NULL;
    ret = true;

exit:
    if (modulus_local != NULL)
        free(modulus_local);

    mbedtls_pk_free(&ctx);

exit_preinit:
    return ret;
}

/**
 * encrypt_gcm encrypts the given data using the given symmetric key.
 * sequence_num is used as additional data to prevent replay attacks
 * Random IV is generated each time.
 */
bool Crypto::encrypt_gcm(
    const uint8_t* sym_key,
    uint32_t sequence_num,
    const uint8_t* data,
    size_t data_size,
    uint8_t* iv_str,
    uint8_t* encrypted_data,
    size_t* encrypted_data_size,
    uint8_t* tag_output)
{
    mbedtls_gcm_context gcm_context;
    uint8_t add_str[ADD_SIZE]; // Sequence number is sent as additional data

    bool result = false;
    int res = -1;
    size_t tag_len = 16;
    size_t add_len = ADD_SIZE;

    if (!m_initialized)
        goto exit;

    mbedtls_gcm_init(&gcm_context);

    // Generate a random IV each time
    memset(iv_str, 0x00, IV_SIZE);
    mbedtls_ctr_drbg_random(&m_ctr_drbg_contex, iv_str, IV_SIZE);
    memset(tag_output, 0x00, 16);
    memset(add_str, 0x00, ADD_SIZE);

    add_str[0] = sequence_num & 0xff;
    add_str[1] = sequence_num & 0xff00;
    add_str[2] = sequence_num & 0xff0000;
    add_str[3] = sequence_num & 0xff000000;

    res = mbedtls_gcm_setkey(&gcm_context, MBEDTLS_CIPHER_ID_AES, sym_key, 256);
    if (res != 0)
    {
        TRACE_ENCLAVE("encrypt_gcm: mbedtls_gcm_setkey failed with %d\n", res);
        goto exit;
    }

    TRACE_ENCLAVE("encrypt_gcm: mbedtls_gcm_setkey succeeded\n");

    res = mbedtls_gcm_crypt_and_tag(
        &gcm_context,
        MBEDTLS_GCM_ENCRYPT,
        data_size,
        iv_str,
        IV_SIZE,
        add_str,
        add_len,
        data,
        encrypted_data,
        tag_len,
        tag_output);

    if (res != 0)
    {
        TRACE_ENCLAVE(
            "encrypt_gcm: mbedtls_gcm_crypt_and_tag failed with %d\n", res);
        goto exit;
    }

    *encrypted_data_size = 16;
    result = true;
exit:
    mbedtls_gcm_free(&gcm_context);
    return result;
}

/**
 * Decrypt_gcm decrypts the given data using the given symmetric key, IV and
 * additional string. Used to decrypt data received from another enclave.
 */
bool Crypto::decrypt_gcm(
    const uint8_t* sym_key,
    const uint8_t* iv_str,
    const uint8_t* add_str,
    const uint8_t* encrypted_data,
    size_t encrypted_data_size,
    const uint8_t* tag_str,
    uint8_t* data,
    size_t* data_size)
{
    mbedtls_gcm_context gcm_context;
    bool result = false;
    int res = 0;
    size_t tag_len = 16;

    if (!m_initialized)
        goto exit;

    mbedtls_gcm_init(&gcm_context);

    res = mbedtls_gcm_setkey(&gcm_context, MBEDTLS_CIPHER_ID_AES, sym_key, 256);
    if (res != 0)
    {
        TRACE_ENCLAVE("Decrypt_gcm: mbedtls_gcm_setkey failed with %d\n", res);
        goto exit;
    }

    res = mbedtls_gcm_auth_decrypt(
        &gcm_context,
        *data_size,
        iv_str,
        IV_SIZE,
        add_str,
        ADD_SIZE,
        tag_str,
        tag_len,
        encrypted_data,
        data);
    if (res != 0)
    {
        TRACE_ENCLAVE(
            "Decrypt_gcm: mbedtls_gcm_auth_decrypt failed with %d\n", res);
        goto exit;
    }

    TRACE_ENCLAVE("Decrypt_gcm: mbedtls_gcm_setkey succeeded\n");

    *data_size = 16;
    result = true;
exit:
    mbedtls_gcm_free(&gcm_context);
    return result;
}

int Crypto::sign(
    const unsigned char* hash_data,
    size_t hash_size,
    unsigned char* sig,
    size_t* sig_len)
{
    int rc = 0;
    int res = -1;
    mbedtls_rsa_context* rsa_context;

    if (!m_initialized)
        goto exit;

    rsa_context = mbedtls_pk_rsa(m_pk_context);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    rc = mbedtls_rsa_pkcs1_sign(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        MBEDTLS_RSA_PRIVATE,
        MBEDTLS_MD_SHA256,
        hash_size,
        hash_data,
        sig);

exit:
    return rc;
}

int Crypto::verify_sign(
    const uint8_t* pem_public_key,
    const unsigned char* hash_data,
    size_t hash_size,
    const unsigned char* sig,
    size_t sig_len)
{
    int rc = 0;
    mbedtls_pk_context key;
    size_t key_size = 0;
    int res = -1;
    mbedtls_rsa_context* rsa_context;

    mbedtls_pk_init(&key);

    if (!m_initialized)
        goto exit;

    res = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_setup failed (%d).", res);
        goto exit;
    }

    // Read the given public key.
    key_size = strlen((const char*)pem_public_key) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_parse_public_key failed.");
        goto exit;
    }

    rsa_context = mbedtls_pk_rsa(key);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    rc = mbedtls_rsa_pkcs1_verify(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        MBEDTLS_RSA_PUBLIC,
        MBEDTLS_MD_SHA256,
        hash_size,
        hash_data,
        sig);
exit:
    mbedtls_pk_free(&key);
    return rc;
}
