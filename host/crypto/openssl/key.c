// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "key.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <string.h>
#include "init.h"

bool oe_private_key_is_valid(const oe_private_key_t* impl, uint64_t magic)
{
    return impl && impl->magic == magic && impl->pkey;
}

bool oe_public_key_is_valid(const oe_public_key_t* impl, uint64_t magic)
{
    return impl && impl->magic == magic && impl->pkey;
}

void oe_public_key_init(
    oe_public_key_t* public_key,
    EVP_PKEY* pkey,
    uint64_t magic)
{
    oe_public_key_t* impl = (oe_public_key_t*)public_key;
    impl->magic = magic;
    impl->pkey = pkey;
}

void oe_private_key_init(
    oe_private_key_t* private_key,
    EVP_PKEY* pkey,
    uint64_t magic)
{
    oe_private_key_t* impl = (oe_private_key_t*)private_key;
    impl->magic = magic;
    impl->pkey = pkey;
}

oe_result_t oe_private_key_from_engine(
    const char *engine_id,
    const char *engine_load_path,
    const char *key_id,
    oe_private_key_t* key,
    int key_type,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    if (impl)
        oe_secure_zero_fill(impl, sizeof(oe_private_key_t));

    /* Check parameters */
    if (!engine_id || !engine_load_path || !key_id || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* if the engine is pre-installed we will get a null */
    ENGINE *e = NULL;
    if (!(e = ENGINE_by_id(engine_id)))
    {
        /* if we got a null we can still load dynaimc. */
        ENGINE_load_dynamic();
        ENGINE *dyne = ENGINE_by_id("dynamic");
        if (!ENGINE_ctrl_cmd_string(dyne, "ID", engine_id, 0))
            OE_RAISE(OE_INVALID_PARAMETER);
        
        if (!ENGINE_ctrl_cmd_string(dyne, "SO_PATH", engine_load_path, 0))
            OE_RAISE(OE_INVALID_PARAMETER);

        if (!ENGINE_ctrl_cmd_string(dyne, "LIST_ADD", "1", 0))
            OE_RAISE(OE_INVALID_PARAMETER);
        if (!ENGINE_ctrl_cmd_string(dyne, "LOAD", NULL, 0))
            OE_RAISE(OE_INVALID_PARAMETER);

        if (!(e = ENGINE_by_id(engine_id)))
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    if (!ENGINE_init(e))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(pkey = ENGINE_load_private_key(e, key_id, NULL, NULL)))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify that it is the right key type */
    if (EVP_PKEY_id(pkey) != key_type)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the key */
    impl->magic = magic;
    impl->pkey = pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_private_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_private_key_t* key,
    int key_type,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    if (impl)
        oe_secure_zero_fill(impl, sizeof(oe_private_key_t));

    /* Check parameters */
    if (!pem_data || !pem_size || pem_size > OE_INT_MAX || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pem_data, (int)pem_size)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Verify that it is the right key type */
    if (EVP_PKEY_id(pkey) != key_type)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the key */
    impl->magic = magic;
    impl->pkey = pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_public_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_public_key_t* key,
    int key_type,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    oe_public_key_t* impl = (oe_public_key_t*)key;

    /* Zero-initialize the key */
    if (impl)
        oe_secure_zero_fill(impl, sizeof(oe_public_key_t));

    /* Check parameters */
    if (!pem_data || !pem_size || pem_size > OE_INT_MAX || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pem_data, (int)pem_size)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Verify that it is the right key type */
    if (EVP_PKEY_id(pkey) != key_type)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the key */
    impl->magic = magic;
    impl->pkey = pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* private_key,
    uint8_t* data,
    size_t* size,
    oe_private_key_write_pem_callback private_key_write_pem_callback,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_private_key_t* impl = (const oe_private_key_t*)private_key;
    BIO* bio = NULL;
    const char null_terminator = '\0';

    /* Check parameters */
    if (!oe_private_key_is_valid(impl, magic) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Write key to BIO */
    OE_CHECK(private_key_write_pem_callback(bio, impl->pkey));

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &null_terminator, sizeof(null_terminator)) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        OE_CHECK(oe_memcpy_s(data, *size, mem->data, mem->length));
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* key,
    uint8_t* data,
    size_t* size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    BIO* bio = NULL;
    const oe_public_key_t* impl = (const oe_public_key_t*)key;
    const char null_terminator = '\0';

    /* Check parameters */
    if (!oe_public_key_is_valid(impl, magic) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, impl->pkey))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &null_terminator, sizeof(null_terminator)) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        OE_CHECK(oe_memcpy_s(data, *size, mem->data, mem->length));
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_private_key_free(oe_private_key_t* key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (key)
    {
        oe_private_key_t* impl = (oe_private_key_t*)key;

        /* Check parameter */
        if (!oe_private_key_is_valid(impl, magic))
            OE_RAISE_NO_TRACE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        if (impl)
            oe_secure_zero_fill(impl, sizeof(oe_private_key_t));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_free(oe_public_key_t* key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (key)
    {
        oe_public_key_t* impl = (oe_public_key_t*)key;

        /* Check parameter */
        if (!oe_public_key_is_valid(impl, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        if (impl)
            oe_secure_zero_fill(impl, sizeof(oe_public_key_t));
    }

    result = OE_OK;

done:
    return result;
}


oe_result_t oe_private_key_sign(
    const oe_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_private_key_t* impl = (const oe_private_key_t*)private_key;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!oe_private_key_is_valid(impl, magic) || !hash_data || !hash_size ||
        !signature_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check that hash buffer is big enough (hash_type is size of that hash) */
    if (hash_type > hash_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Initialize the signing context */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size;

        if (EVP_PKEY_sign(ctx, NULL, &size, hash_data, hash_size) <= 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (size > *signature_size)
        {
            *signature_size = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *signature_size = size;
    }

    /* Compute the signature */
    if (EVP_PKEY_sign(ctx, signature, signature_size, hash_data, hash_size) <=
        0)
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

oe_result_t oe_sign_by_engine(
    const char *engine_id,    // string name of the engine, ie "esrp"
    const char *key_id,       // string id of the desired signing key, ie "KEYCODE=CP-23072"
    const char *engine_load_path, // Location of the 
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY *pkey    = NULL;
    ENGINE *e = NULL;

    /* Check for null parameters */
    if (!engine_id || !key_id  || !hash_data || !hash_size ||
        !signature_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check that hash buffer is big enough (hash_type is size of that hash) */
    if (hash_type > hash_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Load and init the engine. */
    if (engine_load_path)
    {
        /* If the engine load path is set this is a dynamically loaded engine, not built in */
        ENGINE_load_dynamic();
        ENGINE *dyne = ENGINE_by_id("dynamic");
        
        if (!ENGINE_ctrl_cmd_string(dyne, "ID", "esrp", 0))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!ENGINE_ctrl_cmd_string(dyne, "SO_PATH", engine_load_path, 0))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!ENGINE_ctrl_cmd_string(dyne, "LIST_ADD", "1", 0))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!ENGINE_ctrl_cmd_string(dyne, "LOAD", NULL, 0))
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    if (!( e = ENGINE_by_id(engine_id)))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!ENGINE_init(e))
    {
        /* if ENGINE_init failed there is no valid reference to e */
        e = NULL;  
        OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Then get the private key 2do: try to sign using the engine rather 
       than the private key, if possible. */

    if (!(pkey = ENGINE_load_private_key(e, key_id, NULL, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(pkey, e)))
    {
        /* some engines are not capable of performing the signing operation, but some are. 
           If we can, we should use them, but its not an error if we can't */

        if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Initialize the signing context */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size;

        if (EVP_PKEY_sign(ctx, NULL, &size, hash_data, hash_size) <= 0)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (size > *signature_size)
        {
            *signature_size = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *signature_size = size;
    }

    /* Compute the signature */
    if (EVP_PKEY_sign(ctx, signature, signature_size, hash_data, hash_size) <=
        0)
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    if (e)
        ENGINE_finish(e);


    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

oe_result_t oe_public_key_verify(
    const oe_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!oe_public_key_is_valid(impl, magic) || !hash_data || !hash_size ||
        !signature || !signature_size)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Check that hash buffer is big enough (hash_type is size of that hash) */
    if (hash_type > hash_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Initialize the signing context */
    if (EVP_PKEY_verify_init(ctx) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Compute the signature */
    if (EVP_PKEY_verify(ctx, signature, signature_size, hash_data, hash_size) <=
        0)
        OE_RAISE(OE_VERIFY_FAILED);

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}
