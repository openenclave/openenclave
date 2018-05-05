/*
**==============================================================================
**
** PrivateKeyImpl
**
**==============================================================================
*/

typedef struct _PrivateKeyImpl
{
    uint64_t magic;
    mbedtls_pk_context pk;
} PrivateKeyImpl;

OE_STATIC_ASSERT(sizeof(PrivateKeyImpl) <= sizeof(PrivateKey));

OE_INLINE bool _PrivateKeyImplValid(const PrivateKeyImpl* impl)
{
    return impl && impl->magic == PRIVATE_KEY_MAGIC;
}

OE_INLINE void _PrivateKeyImplInit(PrivateKeyImpl* impl)
{
    impl->magic = PRIVATE_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _PrivateKeyImplFree(PrivateKeyImpl* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(PrivateKeyImpl));
    }
}

static OE_Result _PrivateKeyImplInitFrom(
    PrivateKeyImpl* impl,
    const mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;

    _PrivateKeyImplInit(impl);

    if (!impl || !pk)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_CopyKey(&impl->pk, pk, true));

    result = OE_OK;

done:

    if (result != OE_OK)
        _PrivateKeyImplFree(impl);

    return result;
}

/*
**==============================================================================
**
** PublicKeyImpl
**
**==============================================================================
*/

typedef struct _PublicKeyImpl
{
    uint64_t magic;
    mbedtls_pk_context pk;
} PublicKeyImpl;

OE_STATIC_ASSERT(sizeof(PublicKeyImpl) <= sizeof(PublicKey));

OE_INLINE bool _PublicKeyImplValid(const PublicKeyImpl* impl)
{
    return impl && impl->magic == PUBLIC_KEY_MAGIC;
}

OE_INLINE void _PublicKeyImplInit(PublicKeyImpl* impl)
{
    impl->magic = PUBLIC_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _PublicKeyImplFree(PublicKeyImpl* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(PublicKeyImpl));
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

static OE_Result _PublicKeyImplInitFrom(
    PublicKey* publicKey,
    const mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;
    PublicKeyImpl* impl = (PublicKeyImpl*)publicKey;

    _PublicKeyImplInit(impl);

    if (!impl || !pk)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_CopyKey(&impl->pk, pk, false));

    result = OE_OK;

done:

    if (result != OE_OK)
        _PublicKeyImplFree(impl);

    return result;
}

static OE_Result _PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PrivateKey* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKeyImpl* impl = (PrivateKeyImpl*)privateKey;

    /* Initialize the key */
    if (impl)
        _PrivateKeyImplInit(impl);

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
    if (impl->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_KEYTYPE))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _PrivateKeyImplFree(impl);

    return result;
}

static OE_Result _PrivateKeyWritePEM(
    const PrivateKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKeyImpl* impl = (PrivateKeyImpl*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_PrivateKeyImplValid(impl) || !pemSize)
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

static OE_Result _PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PublicKey* publicKey)
{
    PublicKeyImpl* impl = (PublicKeyImpl*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _PublicKeyImplInit(impl);

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
    if (impl->pk.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_KEYTYPE))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _PublicKeyImplFree(impl);

    return result;
}

static OE_Result _PublicKeyWritePEM(
    const PublicKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    PublicKeyImpl* impl = (PublicKeyImpl*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_PublicKeyImplValid(impl) || !pemSize)
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

static OE_Result _PrivateKeyFree(PrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        PrivateKeyImpl* impl = (PrivateKeyImpl*)key;

        if (!_PrivateKeyImplValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _PrivateKeyImplFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

static OE_Result _PublicKeyFree(PublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        PublicKeyImpl* impl = (PublicKeyImpl*)key;

        if (!_PublicKeyImplValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _PublicKeyImplFree(impl);
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
    const PrivateKeyImpl* impl = (const PrivateKeyImpl*)privateKey;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_PrivateKeyImplValid(impl) || !hashData || !hashSize || !signatureSize)
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

static OE_Result _PublicKeyVerify(
    const PublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const PublicKeyImpl* impl = (const PublicKeyImpl*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_PublicKeyImplValid(impl) || !hashData || !hashSize || !signature ||
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
