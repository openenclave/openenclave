// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

#include "common.h"
#include "encryptor.h"

#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false
#define SALT_SIZE_IN_BYTES 16 // Length of salt size

void ECallDispatcher::dumpData(
    const char* name,
    unsigned char* pData,
    size_t dataSize)
{
    ENC_DEBUG_PRINTF("Data name: %s", name);
    for (size_t i = 0; i < dataSize; i++)
    {
        ENC_DEBUG_PRINTF("[%ld]-0x%02X", i, pData[i]);
    }
    ENC_DEBUG_PRINTF("\n");
}

// Compute the sha256 hash of given data.
int ECallDispatcher::Sha256(
    const uint8_t* data,
    size_t dataSize,
    uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, dataSize);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

// This routine uses the mbedTLS library to derive an AES key from the input
// password and produce a password based key. Note : A set of hardcoded salt
// values are used here for the purpose simplifying this sample, which caused
// this routine to return the same key when taking the same password. This saves
// the sample from having to write salt values to the encryption header. In a
// real world application, randomly generated salt values are recommended.
int ECallDispatcher::generatePasswordKey(
    const char* _password,
    unsigned char* _key,
    unsigned int _keyLength)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t* info_sha;
    int ret = 0;
    unsigned char salt[SALT_SIZE_IN_BYTES] = {0xb2,
                                              0x4b,
                                              0xf2,
                                              0xf7,
                                              0x7a,
                                              0xc5,
                                              0xec,
                                              0x0c,
                                              0x5e,
                                              0x1f,
                                              0x4d,
                                              0xc1,
                                              0xae,
                                              0x46,
                                              0x5e,
                                              0x75};
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_md_init(&sha_ctx);

    ENC_DEBUG_PRINTF("generatePasswordKey");

    memset(_key, 0, _keyLength);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == NULL)
    {
        ret = 1;
        goto exit;
    }

    // setting up hash algorithm context
    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_md_setup() failed with -0x%04x", -ret);
        goto exit;
    }

    // Derive a key from a password using PBKDF2.
    // PBKDF2 (Password-Based Key Derivation Function 2) are key derivation
    // functions with a sliding computational cost, aimed to reduce the
    // vulnerability of encrypted keys to brute force attacks. See
    // (https://en.wikipedia.org/wiki/PBKDF2) for more details.
    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &sha_ctx,                        // Generic HMAC context
        (const unsigned char*)_password, // Password to use when generating key
        strlen((const char*)_password),  // Length of password
        salt,                            // salt to use when generating key
        SALT_SIZE_IN_BYTES,              // size of salt
        100000,                          // iteration count
        _keyLength,                      // length of generated key in bytes
        _key);                           // generated key
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_pkcs5_pbkdf2_hmac failed with -0x%04x", -ret);
        goto exit;
    }
    ENC_DEBUG_PRINTF("Key based on password successfully generated");
exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_md_free(&sha_ctx);
    return ret;
}

// Generate an ephemeral key: this is the key used to encrypt data
int ECallDispatcher::generateEncryptionKey(
    unsigned char* _key,
    unsigned int _keyLength)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char pers[] = "EphemeralKey";
    int ret = 0;

    ENC_DEBUG_PRINTF("generateEncryptionKey:");

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(_key, 0, _keyLength);

    // mbedtls_ctr_drbg_seed seeds and sets up the CTR_DRBG entropy source for
    // future reseeds.
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (unsigned char*)pers,
        sizeof(pers));
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_ctr_drbg_init failed with -0x%04x\n", -ret);
        goto exit;
    }

    // mbedtls_ctr_drbg_random uses CTR_DRBG to generate random data
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, _key, _keyLength);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_ctr_drbg_random failed with -0x%04x\n", -ret);
        goto exit;
    }
    ENC_DEBUG_PRINTF(
        "Encryption key successfully generated: a %d byte key (hex):  ",
        _keyLength);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// The encryption key is encrypted before it was written back to the encryption
// header as part of the encryption metadata. Note: using fixed initialization
// vector (iv) is good enough because its used only for the purpose of
// encrypting encryption key, just once.
int ECallDispatcher::cipherEncryptionKey(
    bool bEncrypt,
    unsigned char* pInputData,
    unsigned int inputDataSize,
    unsigned char* encryptKey,
    unsigned char* pOutData,
    unsigned int outputDataSize)
{
    int ret = 0;
    mbedtls_aes_context aescontext;
    unsigned char iv[IV_SIZE] = {0xb2,
                                 0x4b,
                                 0xf2,
                                 0xf7,
                                 0x7a,
                                 0xc5,
                                 0xec,
                                 0x0c,
                                 0x5e,
                                 0x1f,
                                 0x4d,
                                 0xc1,
                                 0xae,
                                 0x46,
                                 0x5e,
                                 0x75};

    ENC_DEBUG_PRINTF(
        "cipherEncryptionKey: %s", bEncrypt ? "encrypting" : "decrypting");

    // init context
    mbedtls_aes_init(&aescontext);

    // set aes key
    ret = mbedtls_aes_setkey_enc(&aescontext, encryptKey, ENCRYPTION_KEY_SIZE);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_aes_setkey_enc failed with %d", ret);
        goto exit;
    }

    ret = mbedtls_aes_crypt_cbc(
        &aescontext,
        bEncrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        inputDataSize, // input data length in bytes,
        iv,            // Initialization vector (updated after use)
        pInputData,
        pOutData);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
exit:
    // free aes context
    mbedtls_aes_free(&aescontext);
    ENC_DEBUG_PRINTF("ECallDispatcher::cipherEncryptionKey");
    return ret;
}

// For an encryption operation, the encryptor creates encryption metadata for
// writing back to the encryption header, which includes the following fields:
// digest: a hash value of the password
// key: encrypted version of the ephemeral key
//
// Operations involves the following operations:
//  1)derive a key from the password
//  2)produce a ephemeral key
//  3)generate a digest for the password
//  4)encrypt the ephemeral key with a password key
//
int ECallDispatcher::prepareEncryptionHeader(
    EncryptionHeader* pHeader,
    string password)
{
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES]; // password derived key
    unsigned char
        passwordKey[ENCRYPTION_KEY_SIZE_IN_BYTES]; // encrypted ephemeral key
    unsigned char encryptedEphemeralKey[ENCRYPTION_KEY_SIZE_IN_BYTES];

    ENC_DEBUG_PRINTF("prepareEncryptionHeader");
    // derive a key from the password using PBDKF2
    ret = generatePasswordKey(
        password.c_str(), passwordKey, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("passwordKey");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            ENC_DEBUG_PRINTF(
                "passwordKey[%d] =0x%02x", i, (unsigned int)(passwordKey[i]));
        goto exit;
    }

    // produce a ephemeral key
    ENC_DEBUG_PRINTF("produce a ephemeral key");
    ret = generateEncryptionKey(
        (unsigned char*)m_encryption_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            ENC_DEBUG_PRINTF(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }

    // generate a digest for the password
    ENC_DEBUG_PRINTF("generate a digest for the password");
    ret = Sha256((const uint8_t*)password.c_str(), password.length(), digest);
    if (ret)
    {
        ENC_DEBUG_PRINTF("Sha256 failed with %d", ret);
        goto exit;
    }

    memcpy(pHeader->digest, digest, ENCRYPTION_KEY_SIZE_IN_BYTES);

    // encrypt the ephemeral key with a password key
    ENC_DEBUG_PRINTF("encrypt the ephemeral key with a psswd key");
    ret = cipherEncryptionKey(
        ENCRYPT_OPERATION,
        m_encryption_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        passwordKey,
        encryptedEphemeralKey,
        ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("EncryptEphemeralKey failed with [%d]", ret);
        goto exit;
    }
    memcpy(
        pHeader->encryptedKey,
        encryptedEphemeralKey,
        ENCRYPTION_KEY_SIZE_IN_BYTES);
    ENC_DEBUG_PRINTF("Done with prepareEncryptionHeader successfully.");
exit:
    return ret;
}

// Parse an input header for validate the password and getting the ephemeral key
// in preparing for decryption/encryption operations
//  1)Check password by comparing their digests
//  2)reproduce a ephemeral key from the password
//  3)decrypt the ephemeral key with a password key
int ECallDispatcher::parseEncryptionHeader(
    EncryptionHeader* pHeader,
    string password)
{
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char passwordkey[ENCRYPTION_KEY_SIZE_IN_BYTES];

    // check password by comparing their digests
    ret =
        Sha256((const uint8_t*)m_Password.c_str(), m_Password.length(), digest);
    if (ret)
    {
        ENC_DEBUG_PRINTF("Sha256 failed with %d", ret);
        goto exit;
    }

    if (memcmp(pHeader->digest, digest, HASH_VALUE_SIZE_IN_BYTES) != 0)
    {
        ENC_DEBUG_PRINTF("incorrect password");
        ret = 1;
        goto exit;
    }

    // derive a key from the password using PBDKF2
    ret = generatePasswordKey(
        password.c_str(), passwordkey, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("generatePasswordKey failed with %d", ret);
        goto exit;
    }
    // decrypt the "encrypted ephemeral key" using the password key
    ret = cipherEncryptionKey(
        DECRYPT_OPERATION,
        pHeader->encryptedKey,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        (unsigned char*)m_encryption_key,
        passwordkey,
        ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            ENC_DEBUG_PRINTF(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }
exit:
    return ret;
}

int ECallDispatcher::processEncryptionHeader(EncryptInitializeArgs* args)
{
    int ret = 0;

    m_Password =
        std::string(args->password, args->password + args->passwordLen);
    m_bEncrypt = args->bEncrypt;
    m_pHeader = args->pHeader;

    if (m_bEncrypt)
    {
        // allocate host memory for the header and it will be returned back to
        // the host
        m_pHeader = (EncryptionHeader*)oe_host_malloc(sizeof(EncryptionHeader));
        if (m_pHeader == NULL)
        {
            ret = 1;
            goto exit;
        }

        ret = prepareEncryptionHeader(m_pHeader, m_Password);
        if (ret != 0)
        {
            ENC_DEBUG_PRINTF("prepareEncryptionHeader failed with %d", ret);
            goto exit;
        }
        args->pHeader = m_pHeader;
    }
    else
    {
        ret = parseEncryptionHeader(m_pHeader, m_Password);
        if (ret != 0)
        {
            ENC_DEBUG_PRINTF("parseEncryptionHeader failed with %d", ret);
            goto exit;
        }
    }
exit:
    return ret;
}