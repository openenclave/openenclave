// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>
#include "../util.h"
#include "init.h"

OE_Result OE_RSAReadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA** key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    RSA* rsa = NULL;

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

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Read the RSA structure from the PEM data */
    if (!(rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Set the output key parameter */
    *key = (OE_RSA*)rsa;
    rsa = NULL;

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_RSAReadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA** key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    RSA* rsa = NULL;
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

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Read the RSA structure from the PEM data */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Get RSA key from public key without increasing reference count */
    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        goto done;

    /* Increase reference count of RSA key */
    RSA_up_ref(rsa);

    /* Set the output key parameter */
    *key = (OE_RSA*)rsa;
    rsa = NULL;

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

void OE_RSAFree(OE_RSA* key)
{
    if (key)
        RSA_free((RSA*)key);
}

OE_Result OE_RSASign(
    const OE_RSA* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = (RSA*)privateKey;

    if (signature)
        *signature = NULL;

    if (signatureSize)
        *signatureSize = 0;

    /* Check for null parameters */
    if (!privateKey || !hash || !signature || !signatureSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Determine the size of the signature */
    *signatureSize = RSA_size(rsa);

    /* Allocate the signature buffer */
    if (!(*signature = (uint8_t*)malloc(*signatureSize)))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Verify that the data is signed by the given RSA private key */
    unsigned int siglen;
    if (!RSA_sign(
            NID_sha256, hash->buf, sizeof(OE_SHA256), *signature, &siglen, rsa))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* This should never happen */
    if (siglen != *signatureSize)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:

    if (result != OE_OK)
    {
        if (signature && *signature)
            free(*signature);

        if (signatureSize)
            *signatureSize = 0;
    }

    return result;
}

OE_Result OE_RSAVerify(
    const OE_RSA* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = (RSA*)publicKey;

    /* Check for null parameters */
    if (!publicKey || !hash || !signature || signatureSize == 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Verify that the data is signed by the given RSA private key */
    if (!RSA_verify(
            NID_sha256,
            hash->buf,
            sizeof(OE_SHA256),
            signature,
            signatureSize,
            rsa))
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_RSAGenerate(
    uint64_t bits,
    uint64_t exponent,
    OE_RSA** privateKey,
    OE_RSA** publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = NULL;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    const char nullTerminator = '\0';

    if (privateKey)
        *privateKey = NULL;

    if (publicKey)
        *publicKey = NULL;

    /* Check parameters */
    if (!privateKey || !publicKey)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check range of bits parameter */
    if (bits > INT_MAX)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check range of exponent parameter */
    if (exponent > ULONG_MAX)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Generate an RSA key pair */
    if (!(rsa = RSA_generate_key(bits, exponent, 0, 0)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Create private key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL))
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

        if (OE_RSAReadPrivateKeyFromPEM(mem->data, mem->length, privateKey) !=
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

        if (!(pkey = EVP_PKEY_new()))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!(EVP_PKEY_assign_RSA(pkey, rsa)))
        {
            result = OE_FAILURE;
            goto done;
        }

        rsa = NULL;

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

        if (OE_RSAReadPublicKeyFromPEM(mem->data, mem->length, publicKey) !=
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

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (result != OE_OK)
    {
        if (privateKey && *privateKey)
        {
            OE_RSAFree(*privateKey);
            *privateKey = NULL;
        }

        if (publicKey && *publicKey)
        {
            OE_RSAFree(*publicKey);
            *publicKey = NULL;
        }
    }

    return result;
}

OE_Result OE_RSAWritePrivateKeyToPEM(
    const OE_RSA* key,
    void** data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = (RSA*)key;
    BIO* bio = NULL;
    const char nullTerminator = '\0';

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!key || !data || !size)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Create memory BIO to write to */
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write key to the BIO */
    if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write a null terminator onto the BIO */
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

OE_Result OE_RSAWritePublicKeyToPEM(
    const OE_RSA* key,
    void** data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = (RSA*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    const char nullTerminator = '\0';

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Create PKEY wrapper structure */
    if (!(pkey = EVP_PKEY_new()))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Assign key into PKEY wrapper structure */
    {
        if (!(EVP_PKEY_assign_RSA(pkey, rsa)))
        {
            result = OE_FAILURE;
            goto done;
        }

        RSA_up_ref(rsa);
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

    if (pkey)
        EVP_PKEY_free(pkey);

    return result;
}
