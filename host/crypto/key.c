// Export a private static function to a public function with a different
// function signature. This permits the implementation structure pointer to
// be different than the public structure pointer.
#define EXPORT_STATIC_FUNCTION(OLD, NEW) \
    extern __typeof(NEW) NEW __attribute__((weak, alias(#OLD)))

typedef struct _PrivateKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} PrivateKey;

OE_STATIC_ASSERT(sizeof(PrivateKey) <= sizeof(PrivateKey));

OE_INLINE bool _PrivateKeyValid(const PrivateKey* impl)
{
    return impl && impl->magic == PRIVATE_KEY_MAGIC && impl->pkey;
}

typedef struct _PublicKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} PublicKey;

OE_STATIC_ASSERT(sizeof(PublicKey) <= sizeof(PublicKey));

OE_INLINE bool _PublicKeyValid(const PublicKey* impl)
{
    return impl && impl->magic == PUBLIC_KEY_MAGIC && impl->pkey;
}

static void _PublicKeyInit(PublicKey* publicKey, EVP_PKEY* pkey)
{
    PublicKey* impl = (PublicKey*)publicKey;
    impl->magic = PUBLIC_KEY_MAGIC;
    impl->pkey = pkey;
}

static OE_Result _PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKey* impl = (PrivateKey*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    if (impl)
        memset(impl, 0, sizeof(*impl));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Verify that it is the right key type */
    if (pkey->type != EVP_PKEY_KEYTYPE)
        OE_RAISE(OE_FAILURE);

    /* Initialize the key */
    impl->magic = PRIVATE_KEY_MAGIC;
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

static OE_Result _PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    PublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    PublicKey* impl = (PublicKey*)key;

    /* Zero-initialize the key */
    if (impl)
        memset(impl, 0, sizeof(*impl));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Verify that it is the right key type */
    if (pkey->type != EVP_PKEY_KEYTYPE)
        OE_RAISE(OE_FAILURE);

    /* Initialize the key */
    impl->magic = PUBLIC_KEY_MAGIC;
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

static OE_Result _PrivateKeyWritePEM(
    const PrivateKey* privateKey,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    const PrivateKey* impl = (const PrivateKey*)privateKey;
    BIO* bio = NULL;
    KEYTYPE* key = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_PrivateKeyValid(impl) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Get key from public key (increasing reference count) */
    if (!(key = EVP_PKEY_get1_KEYTYPE(impl->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Write key to BIO */
    if (!PEM_write_bio_KEYTYPEPrivateKey(bio, key, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_FAILURE);

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    if (key)
        KEYTYPE_free(key);

    return result;
}

static OE_Result _PublicKeyWritePEM(
    const PublicKey* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    const PublicKey* impl = (const PublicKey*)key;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_PublicKeyValid(impl) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, impl->pkey))
        OE_RAISE(OE_FAILURE);

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

static OE_Result _PrivateKeyFree(PrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        PrivateKey* impl = (PrivateKey*)key;

        /* Check parameter */
        if (!_PrivateKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        if (impl)
            memset(impl, 0, sizeof(*impl));
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
        PublicKey* impl = (PublicKey*)key;

        /* Check parameter */
        if (!_PublicKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        if (impl)
            memset(impl, 0, sizeof(*impl));
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
    const PrivateKey* impl = (const PrivateKey*)privateKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!_PrivateKeyValid(impl) || !hashData || !hashSize || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Initialize the signing context */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size;

        if (EVP_PKEY_sign(ctx, NULL, &size, hashData, hashSize) <= 0)
            OE_RAISE(OE_FAILURE);

        if (size > *signatureSize)
        {
            *signatureSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *signatureSize = size;
    }

    /* Compute the signature */
    if (EVP_PKEY_sign(ctx, signature, signatureSize, hashData, hashSize) <= 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

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
    const PublicKey* impl = (const PublicKey*)publicKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!_PublicKeyValid(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Initialize the signing context */
    if (EVP_PKEY_verify_init(ctx) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Compute the signature */
    if (EVP_PKEY_verify(ctx, signature, signatureSize, hashData, hashSize) <= 0)
        OE_RAISE(OE_VERIFY_FAILED);

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}
