// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

// oe_result_t generate_rsa_pair(
//     uint8_t** public_key,
//     size_t* public_key_size,
//     uint8_t** private_key,
//     size_t* private_key_size)
// {
//     oe_result_t result = OE_FAILURE;
//     uint8_t* local_public_key = nullptr;
//     uint8_t* local_private_key = nullptr;
//     int res = -1;
//     EVP_PKEY* pkey = nullptr;
//     RSA* rsa = nullptr;
//     BIO* bio = nullptr;
//     BIGNUM* e = nullptr;

//     // Generate RSA key
//     pkey = EVP_PKEY_new();
//     if (!pkey)
//         OE_RAISE_MSG(OE_FAILURE, "EVP_PKEY_new failed\n");

//     e = BN_new();
//     if (!e)
//         OE_RAISE_MSG(OE_FAILURE, "BN_new failed\n");

//     res = BN_set_word(e, (BN_ULONG)RSA_F4);
//     if (!res)
//         OE_RAISE_MSG(OE_FAILURE, "BN_set_word failed (%d)\n", res);

//     rsa = RSA_new();
//     if (!rsa)
//         OE_RAISE_MSG(OE_FAILURE, "RSA_new failed\n");

//     res = RSA_generate_key_ex(
//         rsa,
//         2048,   /* number of bits for the key value */
//         e,      /* exponent - RSA_F4 is defined as 0x10001L */
//         nullptr /* callback argument - not needed in this case */
//     );

//     if (!res)
//         OE_RAISE_MSG(OE_FAILURE, "RSA_generate_key failed (%d)\n", res);

//     // Assign RSA key to EVP_PKEY structure
//     EVP_PKEY_assign_RSA(pkey, rsa);

//     // Allocate memory
//     local_public_key = (uint8_t*)calloc(1, OE_RSA_PUBLIC_KEY_SIZE);
//     if (local_public_key == nullptr)
//         OE_RAISE(OE_OUT_OF_MEMORY);

//     local_private_key = (uint8_t*)calloc(1, OE_RSA_PRIVATE_KEY_SIZE);
//     if (local_private_key == nullptr)
//         OE_RAISE(OE_OUT_OF_MEMORY);

//     // Write out the public/private key in PEM format for exchange with
//     // other enclaves.
//     bio = BIO_new(BIO_s_mem());
//     if (!bio)
//         OE_RAISE_MSG(OE_FAILURE, "BIO_new for local_public_key failed\n");

//     res = PEM_write_bio_PUBKEY(bio, pkey);
//     if (!res)
//         OE_RAISE_MSG(OE_FAILURE, "PEM_write_bio_PUBKEY failed (%d)\n", res);

//     res = BIO_read(bio, local_public_key, OE_RSA_PUBLIC_KEY_SIZE);
//     if (!res)
//         OE_RAISE_MSG(OE_FAILURE, "BIO_read public key failed (%d)\n", res);

//     BIO_free(bio);
//     bio = nullptr;

//     bio = BIO_new(BIO_s_mem());
//     if (!bio)
//         OE_RAISE_MSG(OE_FAILURE, "BIO_new for local_public_key failed\n");

//     res = PEM_write_bio_PrivateKey(
//         bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
//     if (!res)
//         OE_RAISE_MSG(OE_FAILURE, "PEM_write_bio_PrivateKey failed (%d)\n", res);

//     res = BIO_read(bio, local_private_key, OE_RSA_PRIVATE_KEY_SIZE);
//     if (!res)
//         OE_RAISE_MSG(OE_FAILURE, "BIO_read private key failed (%d)\n", res);

//     BIO_free(bio);
//     bio = nullptr;

//     *public_key = local_public_key;
//     // plus one to make sure \0 at the end is counted
//     *public_key_size = strlen((const char*)local_public_key) + 1;

//     *private_key = local_private_key;
//     *private_key_size = strlen((const char*)local_private_key) + 1;

//     local_public_key = nullptr;
//     local_private_key = nullptr;

//     OE_TRACE_INFO("public_key_size\n[%d]\n", *public_key_size);
//     OE_TRACE_INFO("public_key\n[%s]\n", *public_key);
//     result = OE_OK;

// done:
//     if (local_public_key)
//         free(local_public_key);
//     if (local_private_key)
//         free(local_private_key);
//     if (bio)
//         BIO_free(bio);
//     if (e)
//         BN_free(e);
//     if (pkey)
//         EVP_PKEY_free(pkey); // When this is called, rsa is also freed

//     return result;
// }

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
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    BIO* bio = nullptr;
    BIGNUM* e = nullptr;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        OE_RAISE_MSG(OE_FAILURE, "EVP_PKEY_CTX_new_id failed\n");
    
    res = EVP_PKEY_keygen_init(ctx);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "EVP_PKEY_keygen_init failed\n");
    
    res = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n");
    
    e = BN_new();
    if (!e)
        OE_RAISE_MSG(OE_FAILURE, "BN_new failed\n");
    
    res = BN_set_word(e, (BN_ULONG)RSA_F4);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "BN_set_word failed\n");
    
    res = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "EVP_PKEY_CTX_set_rsa_keygen_pubexp failed\n");
    
    res = EVP_PKEY_keygen(ctx, &pkey);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "EVP_PKEY_keygen failed\n");
    
    local_public_key = (uint8_t*)calloc(1, OE_RSA_PUBLIC_KEY_SIZE);
    if (local_public_key == nullptr)
        OE_RAISE(OE_OUT_OF_MEMORY);

    local_private_key = (uint8_t*)calloc(1, OE_RSA_PRIVATE_KEY_SIZE);
    if (local_private_key == nullptr)
        OE_RAISE(OE_OUT_OF_MEMORY);
    
    bio = BIO_new(BIO_s_mem());
    if (!bio)
        OE_RAISE_MSG(OE_FAILURE, "BIO_new for local_public_key failed\n");

    res = PEM_write_bio_PUBKEY(bio, pkey);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "PEM_write_bio_PUBKEY failed (%d)\n", res);

    res = BIO_read(bio, local_public_key, OE_RSA_PUBLIC_KEY_SIZE);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "BIO_read public key failed (%d)\n", res);

    BIO_free(bio);
    bio = nullptr;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
        OE_RAISE_MSG(OE_FAILURE, "BIO_new for local_public_key failed\n");

    res = PEM_write_bio_PrivateKey(
        bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "PEM_write_bio_PrivateKey failed (%d)\n", res);

    res = BIO_read(bio, local_private_key, OE_RSA_PRIVATE_KEY_SIZE);
    if (!res)
        OE_RAISE_MSG(OE_FAILURE, "BIO_read private key failed (%d)\n", res);

    BIO_free(bio);
    bio = nullptr;

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
    if (bio)
        BIO_free(bio);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return result;
}
