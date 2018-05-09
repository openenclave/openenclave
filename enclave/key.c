// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Used to alias static function to public function names
#define ALIAS(OLD, NEW) extern __typeof(NEW) NEW __attribute__((alias(#OLD)))

/*
**==============================================================================
**
** PrivateKey
**
**==============================================================================
*/

typedef struct _PrivateKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} PrivateKey;

OE_INLINE bool _PrivateKeyValid(const PrivateKey* privateKey)
{
    return privateKey && privateKey->magic == PRIVATE_KEY_MAGIC;
}

static OE_Result _PrivateKeyInit(PrivateKey* privateKey, mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;

    if (!privateKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    privateKey->magic = 0;

    if (pk)
        OE_CHECK(_CopyKey(&privateKey->pk, pk, true));
    else
        mbedtls_pk_init(&privateKey->pk);

    privateKey->magic = PRIVATE_KEY_MAGIC;

    result = OE_OK;

done:
    return result;
}

OE_INLINE void _PrivateKeyRelease(PrivateKey* privateKey)
{
    if (privateKey && privateKey->magic == PRIVATE_KEY_MAGIC)
    {
        mbedtls_pk_free(&privateKey->pk);
        OE_Memset(privateKey, 0, sizeof(PrivateKey));
    }
}

/*
**==============================================================================
**
** PublicKey
**
**==============================================================================
*/

typedef struct _PublicKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} PublicKey;

OE_INLINE bool _PublicKeyValid(const PublicKey* publicKey)
{
    return publicKey && publicKey->magic == PUBLIC_KEY_MAGIC;
}

static OE_Result _PublicKeyInit(PublicKey* publicKey, mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;

    if (!publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    publicKey->magic = 0;

    if (pk)
        OE_CHECK(_CopyKey(&publicKey->pk, pk, false));
    else
        mbedtls_pk_init(&publicKey->pk);

    publicKey->magic = PUBLIC_KEY_MAGIC;

    result = OE_OK;

done:
    return result;
}

OE_INLINE void _PublicKeyRelease(PublicKey* publicKey)
{
    if (publicKey && publicKey->magic == PUBLIC_KEY_MAGIC)
    {
        mbedtls_pk_free(&publicKey->pk);
        OE_Memset(publicKey, 0, sizeof(PublicKey));
    }
}

/*
**==============================================================================
**
** _MapHashType()
**
**==============================================================================
*/

static mbedtls_md_type_t _MapHashType(OE_HashType md)
{
    switch (md)
    {
        case OE_HASH_TYPE_SHA256:
            return MBEDTLS_MD_SHA256;
        case OE_HASH_TYPE_SHA512:
            return MBEDTLS_MD_SHA512;
    }

    /* Unreachable */
    return 0;
}

/*
**==============================================================================
**
** Public functions:
**
**==============================================================================
*/

static OE_Result _PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PrivateKey* privateKey)
{
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (privateKey)
        OE_CHECK(_PrivateKeyInit(privateKey, NULL));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !privateKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&privateKey->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain this type of key */
    if (privateKey->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_KEYTYPE))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _PrivateKeyRelease(privateKey);

    return result;
}

static OE_Result _PrivateKeyWritePEM(
    const PrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_PrivateKeyValid(privateKey) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_key_pem(
            (mbedtls_pk_context*)&privateKey->pk, buf, sizeof(buf)) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

static OE_Result _PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (publicKey)
        OE_CHECK(_PublicKeyInit(publicKey, NULL));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&publicKey->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (publicKey->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_KEYTYPE))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _PublicKeyRelease(publicKey);

    return result;
}

static OE_Result _PublicKeyWritePEM(
    const PublicKey* publicKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_PublicKeyValid(publicKey) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
    if (mbedtls_pk_write_pubkey_pem(
            (mbedtls_pk_context*)&publicKey->pk, buf, sizeof(buf)) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

static OE_Result _PrivateKeyFree(PrivateKey* privateKey)
{
    OE_Result result = OE_UNEXPECTED;

    if (privateKey)
    {
        if (!_PrivateKeyValid(privateKey))
            OE_RAISE(OE_INVALID_PARAMETER);

        _PrivateKeyRelease(privateKey);
    }

    result = OE_OK;

done:
    return result;
}

static OE_Result _PublicKeyFree(PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;

    if (publicKey)
    {
        if (!_PublicKeyValid(publicKey))
            OE_RAISE(OE_INVALID_PARAMETER);

        _PublicKeyRelease(publicKey);
    }

    result = OE_OK;

done:
    return result;
}

static OE_Result _PrivateKeySign(
    const PrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_PrivateKeyValid(privateKey) || !hashData || !hashSize ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Sign the message. Note that bufferSize is an output parameter only.
    // MEBEDTLS provides no way to determine the size of the buffer up front.
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)&privateKey->pk,
            type,
            hashData,
            hashSize,
            buffer,
            &bufferSize,
            NULL,
            NULL) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    // If signature buffer parameter is too small:
    if (*signatureSize < bufferSize)
    {
        *signatureSize = bufferSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy result to output buffer */
    OE_Memcpy(signature, buffer, bufferSize);
    *signatureSize = bufferSize;

    result = OE_OK;

done:

    return result;
}

static OE_Result _PublicKeyVerify(
    const PublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_PublicKeyValid(publicKey) || !hashData || !hashSize || !signature ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&publicKey->pk,
            type,
            hashData,
            hashSize,
            signature,
            signatureSize) != 0)
    {
        OE_RAISE(OE_VERIFY_FAILED);
    }

    result = OE_OK;

done:

    return result;
}
