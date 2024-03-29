// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if !defined(OE_BUILD_ENCLAVE)
#include <openenclave/internal/crypto/init.h>
#endif
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "ec.h"
#include "key.h"
#include "magic.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed for compatibility with ssl1.1 */
static int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_ec_private_key_t));

static int _get_nid(oe_ec_type_t ec_type)
{
    switch (ec_type)
    {
        case OE_EC_TYPE_SECP256R1:
            return NID_X9_62_prime256v1;
        default:
            return NID_undef;
    }
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static oe_result_t _private_key_write_pem_callback(BIO* bio, EVP_PKEY* pkey)
{
    oe_result_t result = OE_UNEXPECTED;
    EC_KEY* ec = NULL;

    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    return result;
}
#else
static oe_result_t _private_key_write_pem_callback(BIO* bio, EVP_PKEY* pkey)
{
    oe_result_t result = OE_UNEXPECTED;
    unsigned char* buffer = NULL;
    size_t bytes_written = 0;
    OSSL_ENCODER_CTX* ctx = NULL;

    ctx = OSSL_ENCODER_CTX_new_for_pkey(
        pkey, EVP_PKEY_KEYPAIR, "PEM", NULL, NULL);

    if (!ctx)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!OSSL_ENCODER_to_data(ctx, &buffer, &bytes_written))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (buffer == NULL || bytes_written == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!BIO_write(bio, buffer, (int)bytes_written))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:

    if (ctx)
        OSSL_ENCODER_CTX_free(ctx);

    if (buffer)
        OPENSSL_free(buffer);

    return result;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static oe_result_t _public_key_equal(
    const oe_public_key_t* public_key1,
    const oe_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;
    EC_KEY* ec1 = NULL;
    EC_KEY* ec2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(public_key1, OE_EC_PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(public_key2, OE_EC_PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ec1 = EVP_PKEY_get1_EC_KEY(public_key1->pkey);
        ec2 = EVP_PKEY_get1_EC_KEY(public_key2->pkey);
        const EC_GROUP* group1 = EC_KEY_get0_group(ec1);
        const EC_GROUP* group2 = EC_KEY_get0_group(ec2);
        const EC_POINT* point1 = EC_KEY_get0_public_key(ec1);
        const EC_POINT* point2 = EC_KEY_get0_public_key(ec2);

        if (!ec1 || !ec2 || !group1 || !group2 || !point1 || !point2)
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Compare group and public key point */
        if (EC_GROUP_cmp(group1, group2, NULL) == 0 &&
            EC_POINT_cmp(group1, point1, point2, NULL) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:

    if (ec1)
        EC_KEY_free(ec1);

    if (ec2)
        EC_KEY_free(ec2);

    return result;
}
#else
static oe_result_t _public_key_equal(
    const oe_public_key_t* public_key1,
    const oe_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(public_key1, OE_EC_PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(public_key2, OE_EC_PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        if (EVP_PKEY_get_id(public_key1->pkey) != EVP_PKEY_EC ||
            EVP_PKEY_get_id(public_key2->pkey) != EVP_PKEY_EC)
            OE_RAISE(OE_CRYPTO_ERROR);

        if (EVP_PKEY_eq(public_key1->pkey, public_key2->pkey))
            *equal = true;
    }

    result = OE_OK;

done:
    return result;
}
#endif

void oe_ec_public_key_init(oe_ec_public_key_t* public_key, EVP_PKEY* pkey)
{
    oe_public_key_init(
        (oe_public_key_t*)public_key, pkey, OE_EC_PUBLIC_KEY_MAGIC);
}

void oe_ec_private_key_init(oe_ec_private_key_t* private_key, EVP_PKEY* pkey)
{
    oe_private_key_init(
        (oe_private_key_t*)private_key, pkey, OE_EC_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_private_key_read_pem(
        pem_data,
        pem_size,
        (oe_private_key_t*)private_key,
        EVP_PKEY_EC,
        OE_EC_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)private_key,
        pem_data,
        pem_size,
        _private_key_write_pem_callback,
        OE_EC_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_read_pem(
    oe_ec_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_public_key_read_pem(
        pem_data,
        pem_size,
        (oe_public_key_t*)public_key,
        EVP_PKEY_EC,
        OE_EC_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)public_key,
        pem_data,
        pem_size,
        OE_EC_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* private_key)
{
    return oe_private_key_free(
        (oe_private_key_t*)private_key, OE_EC_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key)
{
    return oe_public_key_free(
        (oe_public_key_t*)public_key, OE_EC_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    return oe_private_key_sign(
        (oe_private_key_t*)private_key,
        hash_type,
        hash_data,
        hash_size,
        signature,
        signature_size,
        OE_EC_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    return oe_public_key_verify(
        (oe_public_key_t*)public_key,
        hash_type,
        hash_data,
        hash_size,
        signature,
        signature_size,
        OE_EC_PUBLIC_KEY_MAGIC);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_ec_generate_key_pair_from_private(
    oe_ec_type_t curve,
    const uint8_t* private_key_buf,
    size_t private_key_buf_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    int openssl_result;
    EC_KEY* key = NULL;
    BIGNUM* private_bn = NULL;
    EC_POINT* public_point = NULL;
    EVP_PKEY* public_pkey = NULL;
    EVP_PKEY* private_pkey = NULL;

    if (!private_key_buf || !private_key || !public_key ||
        private_key_buf_size > OE_INT_MAX)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Initialize the EC key. */
    key = EC_KEY_new_by_curve_name(_get_nid(curve));
    if (key == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Set the EC named-curve flag. */
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    /* Load private key into the EC key. */
    private_bn = BN_bin2bn(private_key_buf, (int)private_key_buf_size, NULL);

    if (private_bn == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EC_KEY_set_private_key(key, private_bn) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    public_point = EC_POINT_new(EC_KEY_get0_group(key));
    if (public_point == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);

    /*
     * To get the public key, we perform the elliptical curve point
     * multiplication with the factors being the private key and the base
     * generator point of the curve.
     */
    openssl_result = EC_POINT_mul(
        EC_KEY_get0_group(key), public_point, private_bn, NULL, NULL, NULL);
    if (openssl_result == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Sanity check the params. */
    if (EC_KEY_set_public_key(key, public_point) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EC_KEY_check_key(key) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Map the key to the EVP_PKEY wrapper. */
    public_pkey = EVP_PKEY_new();
    if (public_pkey == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EVP_PKEY_set1_EC_KEY(public_pkey, key) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    private_pkey = EVP_PKEY_new();
    if (private_pkey == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EVP_PKEY_set1_EC_KEY(private_pkey, key) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    oe_ec_public_key_init(public_key, public_pkey);
    oe_ec_private_key_init(private_key, private_pkey);
    public_pkey = NULL;
    private_pkey = NULL;
    result = OE_OK;

done:
    if (key != NULL)
        EC_KEY_free(key);
    if (private_bn != NULL)
        BN_clear_free(private_bn);
    if (public_point != NULL)
        EC_POINT_clear_free(public_point);
    if (public_pkey != NULL)
        EVP_PKEY_free(public_pkey);
    if (private_pkey != NULL)
        EVP_PKEY_free(private_pkey);
    return result;
}
#else
oe_result_t oe_ec_generate_key_pair_from_private(
    oe_ec_type_t curve,
    const uint8_t* private_key_buf,
    size_t private_key_buf_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    EC_GROUP* group = NULL;
    EVP_PKEY_CTX* public_ctx = NULL;
    EVP_PKEY_CTX* private_ctx = NULL;
    EVP_PKEY* public_pkey = NULL;
    EVP_PKEY* private_pkey = NULL;
    BIGNUM* private_key_bn = NULL;
    EC_POINT* point = NULL;
    uint8_t* buffer = NULL;
    size_t keysize = 0;
    OSSL_PARAM_BLD* bld = NULL;
    OSSL_PARAM* params = NULL;

    if (!private_key_buf || !private_key || !public_key ||
        private_key_buf_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(group = EC_GROUP_new_by_curve_name(_get_nid(curve))))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Allocate point */
    if (!(point = EC_POINT_new(group)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Convert private key to BIGNUM */
    if (!(private_key_bn =
              BN_bin2bn(private_key_buf, (int)private_key_buf_size, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Get public point by multiplying with base generator */
    if (!EC_POINT_mul(group, point, private_key_bn, NULL, NULL, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    keysize = EC_POINT_point2oct(
        group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (keysize == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!(buffer = OPENSSL_malloc(keysize)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (EC_POINT_point2oct(
            group,
            point,
            POINT_CONVERSION_UNCOMPRESSED,
            buffer,
            keysize,
            NULL) > 1024)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!(private_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EVP_PKEY_fromdata_init(private_ctx) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    bld = OSSL_PARAM_BLD_new();
    if (!OSSL_PARAM_BLD_push_utf8_string(
            bld, "group", (char*)OBJ_nid2sn(_get_nid(curve)), 0))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!OSSL_PARAM_BLD_push_BN(bld, "priv", private_key_bn))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!OSSL_PARAM_BLD_push_octet_string(bld, "pub", buffer, keysize))
        OE_RAISE(OE_CRYPTO_ERROR);

    params = OSSL_PARAM_BLD_to_param(bld);
    if (EVP_PKEY_fromdata(
            private_ctx, &private_pkey, EVP_PKEY_KEYPAIR, params) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!(public_ctx = EVP_PKEY_CTX_new(private_pkey, NULL)))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EVP_PKEY_check(public_ctx) != 1)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!(public_pkey = EVP_PKEY_dup(private_pkey)))
        OE_RAISE(OE_CRYPTO_ERROR);

    oe_ec_public_key_init(public_key, public_pkey);
    oe_ec_private_key_init(private_key, private_pkey);
    public_pkey = NULL;
    private_pkey = NULL;
    result = OE_OK;

done:
    if (buffer)
        OPENSSL_free(buffer);
    if (bld)
        OSSL_PARAM_BLD_free(bld);
    if (params)
        OSSL_PARAM_free(params);
    if (private_key_bn)
        BN_free(private_key_bn);
    if (point)
        EC_POINT_free(point);
    if (group)
        EC_GROUP_free(group);
    if (public_ctx)
        EVP_PKEY_CTX_free(public_ctx);
    if (private_ctx)
        EVP_PKEY_CTX_free(private_ctx);
    if (public_pkey)
        EVP_PKEY_free(public_pkey);
    if (private_pkey)
        EVP_PKEY_free(private_pkey);
    return result;
}
#endif

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* public_key1,
    const oe_ec_public_key_t* public_key2,
    bool* equal)
{
    return _public_key_equal(
        (oe_public_key_t*)public_key1, (oe_public_key_t*)public_key2, equal);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* public_key,
    oe_ec_type_t ec_type,
    const uint8_t* x_data,
    size_t x_size,
    const uint8_t* y_data,
    size_t y_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_public_key_t* impl = (oe_public_key_t*)public_key;
    int nid;
    EC_KEY* ec = NULL;
    EVP_PKEY* pkey = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* point = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!public_key || !x_data || !x_size || x_size > OE_INT_MAX || !y_data ||
        !y_size || y_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the NID for this curve type */
    if ((nid = _get_nid(ec_type)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the public EC key */
    {
        if (!(group = EC_GROUP_new_by_curve_name(nid)))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!(ec = EC_KEY_new()))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!(EC_KEY_set_group(ec, group)))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!(point = EC_POINT_new(group)))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!(x = BN_new()) || !(y = BN_new()))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!(BN_bin2bn(x_data, (int)x_size, x)))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!(BN_bin2bn(y_data, (int)y_size, y)))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (!EC_KEY_set_public_key(ec, point))
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Create the PKEY public key wrapper */
    {
        /* Create the public key structure */
        if (!(pkey = EVP_PKEY_new()))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Initialize the public key from the generated key pair */
        {
            if (!EVP_PKEY_assign_EC_KEY(pkey, ec))
                OE_RAISE(OE_CRYPTO_ERROR);

            ec = NULL;
        }

        /* Initialize the public key */
        {
            oe_public_key_init(impl, pkey, OE_EC_PUBLIC_KEY_MAGIC);
            pkey = NULL;
        }
    }

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    if (group)
        EC_GROUP_free(group);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (x)
        BN_free(x);

    if (y)
        BN_free(y);

    if (point)
        EC_POINT_free(point);

    return result;
}
#else
oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* public_key,
    oe_ec_type_t ec_type,
    const uint8_t* x_data,
    size_t x_size,
    const uint8_t* y_data,
    size_t y_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_public_key_t* impl = (oe_public_key_t*)public_key;
    int nid;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM_BLD* param_bld = NULL;
    OSSL_PARAM* params = NULL;
    unsigned char* pub_data = NULL;

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameter */
    if (!public_key || !x_data || !x_size || x_size > OE_INT_MAX || !y_data ||
        !y_size || y_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the NID for this curve type */
    if ((nid = _get_nid(ec_type)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the public EC key */
    if (!(param_bld = OSSL_PARAM_BLD_new()))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!OSSL_PARAM_BLD_push_utf8_string(
            param_bld, "group", OBJ_nid2sn(nid), 0))
        OE_RAISE(OE_CRYPTO_ERROR);

    pub_data = OPENSSL_malloc(1 + x_size + y_size);
    if (!pub_data)
        OE_RAISE(OE_OUT_OF_MEMORY);

    pub_data[0] = (uint8_t)POINT_CONVERSION_UNCOMPRESSED;
    memcpy(&pub_data[1], &x_data[0], x_size);
    memcpy(&pub_data[1 + x_size], &y_data[0], y_size);

    if (!OSSL_PARAM_BLD_push_octet_string(
            param_bld, "pub", pub_data, 1 + x_size + y_size))
        OE_RAISE(OE_CRYPTO_ERROR);

    params = OSSL_PARAM_BLD_to_param(param_bld);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL || params == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    oe_public_key_init(impl, pkey, OE_EC_PUBLIC_KEY_MAGIC);
    pkey = NULL;
    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    if (params)
        OSSL_PARAM_free(params);

    if (param_bld)
        OSSL_PARAM_BLD_free(param_bld);

    if (pub_data)
        OPENSSL_free(pub_data);

    return result;
}
#endif

oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signature_size,
    const uint8_t* data,
    size_t size,
    const uint8_t* s_data,
    size_t s_size)
{
    oe_result_t result = OE_UNEXPECTED;
    ECDSA_SIG* sig = NULL;
    int sig_len;
    BIGNUM* sig_r = NULL;
    BIGNUM* sig_s = NULL;

    /* Reject invalid parameters */
    if (!signature_size || !data || !size || size > OE_INT_MAX || !s_data ||
        !s_size || s_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature is null, then signature_size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create new signature object */
    if (!(sig = ECDSA_SIG_new()))
        OE_RAISE(OE_CRYPTO_ERROR);

    sig_r = BN_new();
    sig_s = BN_new();
    /* Convert R to big number object */
    if (!(BN_bin2bn(data, (int)size, (BIGNUM*)sig_r)))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Convert S to big number object */
    if (!(BN_bin2bn(s_data, (int)s_size, (BIGNUM*)sig_s)))
        OE_RAISE(OE_CRYPTO_ERROR);

    ECDSA_SIG_set0(sig, sig_r, sig_s);

    /* Determine the size of the binary signature */
    if ((sig_len = i2d_ECDSA_SIG(sig, NULL)) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Copy binary signature to output buffer */
    if (signature && ((size_t)sig_len <= *signature_size))
    {
        uint8_t* p = signature;

        if (!i2d_ECDSA_SIG(sig, &p))
            OE_RAISE(OE_CRYPTO_ERROR);

        if (p - signature != sig_len)
            OE_RAISE(OE_FAILURE);
    }

    /* Check whether buffer is too small */
    if ((size_t)sig_len > *signature_size)
    {
        *signature_size = (size_t)sig_len;

        if (signature)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        /* If signature is null, this call is intented to get the correct
         * signature_size so no need to trace OE_BUFFER_TOO_SMALL */
        else
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    /* Set the size of the output buffer */
    *signature_size = (size_t)sig_len;

    result = OE_OK;

done:

    if (sig)
        ECDSA_SIG_free(sig);

    return result;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
bool oe_ec_valid_raw_private_key(
    oe_ec_type_t type,
    const uint8_t* key,
    size_t keysize)
{
    BIGNUM* bn = NULL;
    EC_GROUP* group = NULL;
    BIGNUM* order = NULL;
    bool is_valid = false;

    if (!key || keysize > OE_INT_MAX)
        goto done;

    bn = BN_bin2bn(key, (int)keysize, NULL);
    if (bn == NULL)
        goto done;

    order = BN_new();
    if (order == NULL)
        goto done;

    group = EC_GROUP_new_by_curve_name(_get_nid(type));
    if (group == NULL)
        goto done;

    if (EC_GROUP_get_order(group, order, NULL) == 0)
        goto done;

    /* Constraint is 1 <= private_key <= order - 1. */
    if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0)
        goto done;

    is_valid = true;

done:
    if (bn != NULL)
        BN_clear_free(bn);
    if (group != NULL)
        EC_GROUP_clear_free(group);
    if (order != NULL)
        BN_clear_free(order);
    return is_valid;
}
#else
bool oe_ec_valid_raw_private_key(
    oe_ec_type_t type,
    const uint8_t* key,
    size_t keysize)
{
    BIGNUM* bn = NULL;
    EC_GROUP* group = NULL;
    BIGNUM* order = NULL;
    bool is_valid = false;

    if (!key || keysize > OE_INT_MAX)
        goto done;

    bn = BN_bin2bn(key, (int)keysize, NULL);
    if (bn == NULL)
        goto done;

    order = BN_new();
    if (order == NULL)
        goto done;

    group = EC_GROUP_new_by_curve_name(_get_nid(type));
    if (group == NULL)
        goto done;

    if (EC_GROUP_get_order(group, order, NULL) == 0)
        goto done;

    /* Constraint is 1 <= private_key <= order - 1. */
    if (BN_is_zero(bn) || BN_cmp(bn, order) >= 0)
        goto done;

    is_valid = true;

done:
    if (bn != NULL)
        BN_clear_free(bn);
    if (group != NULL)
        EC_GROUP_free(group);
    if (order != NULL)
        BN_clear_free(order);
    return is_valid;
}
#endif
