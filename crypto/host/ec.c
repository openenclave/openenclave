#include <openenclave/bits/ec.h>
#include <openenclave/bits/sha.h>
#include <openenclave/types.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include "init.h"
#include "../util.h"

OE_Result OE_ECReadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_EC** key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    if (key)
        *key = NULL;

    /* Check parameters */
    if (!pemData || pemSize == 0 || !key)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        goto done;

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        goto done;

    *key = (OE_EC*)pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_ECReadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_EC** key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    if (key)
        *key = NULL;

    /* Check parameters */
    if (!pemData || pemSize == 0 || !key)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        goto done;

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        goto done;

    *key = (OE_EC*)pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

void OE_ECFree(OE_EC* key)
{
    if (key)
        EVP_PKEY_free((EVP_PKEY*)key);
}

OE_Result OE_ECSign(
    OE_EC* key,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    EVP_PKEY* pkey = (EVP_PKEY*)key;
    EVP_PKEY_CTX* ctx = NULL;

    if (signature)
        *signature = NULL;

    if (signatureSize)
        *signatureSize = 0;

    /* Check for null parameters */
    if (!key || !signature || !hash || !signature || !signatureSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto done;

    /* Initialize the signing context */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        goto done;

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    /* Determine the size of the signature buffer */
    if (EVP_PKEY_sign(ctx, NULL, signatureSize, hash->buf, sizeof(OE_SHA256)) <=
        0)
    {
        goto done;
    }

    /* Allocate the signature buffer */
    if (!(*signature = (uint8_t*)malloc(*signatureSize)))
    {
        *signatureSize = 0;
        goto done;
    }

    /* Compute the signature */
    if (EVP_PKEY_sign(
            ctx, *signature, signatureSize, hash->buf, sizeof(OE_SHA256)) <= 0)
    {
        free(*signature);
        *signature = NULL;
        *signatureSize = 0;
        goto done;
    }

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

OE_Result OE_ECVerify(
    OE_EC* key,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    EVP_PKEY* pkey = (EVP_PKEY*)key;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!key || !signature || !hash || !signature || !signatureSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto done;

    /* Initialize the signing context */
    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto done;

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    /* Compute the signature */
    if (EVP_PKEY_verify(
            ctx, signature, signatureSize, hash->buf, sizeof(OE_SHA256)) <= 0)
    {
        goto done;
    }

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

OE_Result OE_ECGenerate(
    const char* curveName,
    OE_EC** privateKey,
    OE_EC** publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    int nid;
    EC_KEY* key = NULL;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;
    const char nullTerminator = '\0';

    if (privateKey)
        *privateKey = NULL;

    if (publicKey)
        *publicKey = NULL;

    if (!privateKey || !publicKey || !curveName)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Resolve the NID for this curve name */
    if ((nid = OBJ_txt2nid(curveName)) == NID_undef)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Create the key */
    if (!(key = EC_KEY_new_by_curve_name(nid)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Set the EC named-curve flag */
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    /* Generate the public/private key pair */
    if (!EC_KEY_generate_key(key))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Create the private key structure */
    if (!(pkey = EVP_PKEY_new()))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Initialize the private key from the generated key pair */
    if (!EVP_PKEY_assign_EC_KEY(pkey, key))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Key will be released when pkey is released */
    key = NULL;

    /* Create private key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!BIO_get_mem_ptr(bio, &mem))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (OE_ECReadPrivateKeyFromPEM(mem->data, mem->length, privateKey) !=
            OE_OK)
        {
            result = OE_FAILURE;
            goto done;
        }

        BIO_free(bio);
        bio = NULL;
    }

    /* Create public key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!PEM_write_bio_PUBKEY(bio, pkey))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        BIO_get_mem_ptr(bio, &mem);

        if (OE_ECReadPublicKeyFromPEM(mem->data, mem->length, publicKey) !=
            OE_OK)
        {
            result = OE_FAILURE;
            goto done;
        }

        BIO_free(bio);
        bio = NULL;
    }

    result = OE_OK;

done:

    if (key)
        EC_KEY_free(key);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    if (result != OE_OK)
    {
        if (privateKey && *privateKey)
        {
            OE_ECFree(*privateKey);
            *privateKey = NULL;
        }

        if (publicKey && *publicKey)
        {
            OE_ECFree(*publicKey);
            *publicKey = NULL;
        }
    }

    return result;
}

OE_Result OE_ECWritePrivateKeyToPEM(
    const OE_EC* key,
    void** data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = (EVP_PKEY*)key;
    EC_KEY* ec;
    const char nullTerminator = '\0';

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Get EC key from public key without increasing reference count */
    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
        goto done;

    /* Write key to BIO */
    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Copy the BIO into memory */
    {
        BUF_MEM* mem;
        void* ptr;

        if (!BIO_get_mem_ptr(bio, &mem))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!(ptr = malloc(mem->length)))
        {
            result = OE_OUT_OF_MEMORY;
            goto done;
        }

        memcpy(ptr, mem->data, mem->length);
        *data = ptr;
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_ECWritePublicKeyToPEM(
    const OE_EC* key,
    void** data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = (EVP_PKEY*)key;
    const char nullTerminator = '\0';

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, pkey))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Copy the BIO into memory */
    {
        BUF_MEM* mem;
        void* ptr;

        if (!BIO_get_mem_ptr(bio, &mem))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!(ptr = malloc(mem->length)))
        {
            result = OE_OUT_OF_MEMORY;
            goto done;
        }

        memcpy(ptr, mem->data, mem->length);
        *data = ptr;
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}
