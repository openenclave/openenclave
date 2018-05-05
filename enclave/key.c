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

OE_STATIC_ASSERT(sizeof(PrivateKey) <= sizeof(PRIVATE_KEY));

OE_INLINE bool _PrivateKeyValid(const PrivateKey* impl)
{
    return impl && impl->magic == PRIVATE_KEY_MAGIC;
}

OE_INLINE void _PrivateKeyInit(PrivateKey* impl)
{
    impl->magic = PRIVATE_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _PrivateKeyFree(PrivateKey* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(PrivateKey));
    }
}

static OE_Result _PrivateKeyInitFrom(
    PrivateKey* impl,
    const mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;

    _PrivateKeyInit(impl);

    if (!impl || !pk)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_CopyKey(&impl->pk, pk, true));

    result = OE_OK;

done:

    if (result != OE_OK)
        _PrivateKeyFree(impl);

    return result;
}

OE_INLINE void _PrivateKeyClear(PrivateKey* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(PrivateKey));
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

OE_STATIC_ASSERT(sizeof(PublicKey) <= sizeof(PUBLIC_KEY));

OE_INLINE bool _PublicKeyValid(const PublicKey* impl)
{
    return impl && impl->magic == PUBLIC_KEY_MAGIC;
}

OE_INLINE void _PublicKeyInit(PublicKey* impl)
{
    impl->magic = PUBLIC_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _PublicKeyFree(PublicKey* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(PublicKey));
    }
}

OE_INLINE void _PublicKeyClear(PublicKey* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(PublicKey));
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

OE_Result OE_PASTE(PUBLIC_KEY, InitFrom)(
    PUBLIC_KEY* publicKey,
    const mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;
    PublicKey* impl = (PublicKey*)publicKey;

    _PublicKeyInit(impl);

    if (!impl || !pk)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_CopyKey(&impl->pk, pk, false));

    result = OE_OK;

done:

    if (result != OE_OK)
        _PublicKeyFree(impl);

    return result;
}

OE_Result OE_PASTE(
    PRIVATE_KEY,
    ReadPEM)(const uint8_t* pemData, size_t pemSize, PRIVATE_KEY* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKey* impl = (PrivateKey*)privateKey;

    /* Initialize the key */
    if (impl)
        _PrivateKeyInit(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain this type of key */
    if (!IS_KEY_FUNCTION(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _PrivateKeyFree(impl);

    return result;
}

OE_Result OE_PASTE(
    PRIVATE_KEY,
    WritePEM)(const PRIVATE_KEY* key, uint8_t* pemData, size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKey* impl = (PrivateKey*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_PrivateKeyValid(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_key_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_RAISE(OE_FAILURE);

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

OE_Result OE_PASTE(
    PUBLIC_KEY,
    ReadPEM)(const uint8_t* pemData, size_t pemSize, PUBLIC_KEY* publicKey)
{
    PublicKey* impl = (PublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _PublicKeyInit(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (!IS_KEY_FUNCTION(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _PublicKeyFree(impl);

    return result;
}

OE_Result OE_PASTE(
    PUBLIC_KEY,
    WritePEM)(const PUBLIC_KEY* key, uint8_t* pemData, size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    PublicKey* impl = (PublicKey*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_PublicKeyValid(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
    if (mbedtls_pk_write_pubkey_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_RAISE(OE_FAILURE);

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

OE_Result OE_PASTE(PRIVATE_KEY, Free)(PRIVATE_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        PrivateKey* impl = (PrivateKey*)key;

        if (!_PrivateKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _PrivateKeyFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_PASTE(PUBLIC_KEY, Free)(PUBLIC_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        PublicKey* impl = (PublicKey*)key;

        if (!_PublicKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _PublicKeyFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_PASTE(PRIVATE_KEY, Sign)(
    const PRIVATE_KEY* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const PrivateKey* impl = (const PrivateKey*)privateKey;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_PrivateKeyValid(impl) || !hashData || !hashSize || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Sign the message. Note that bufferSize is an output parameter only.
    // MEBEDTLS provides no way to determine the size of the buffer up front.
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)&impl->pk,
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

OE_Result OE_PASTE(PUBLIC_KEY, Verify)(
    const PUBLIC_KEY* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const PublicKey* impl = (const PublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_PublicKeyValid(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&impl->pk,
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
