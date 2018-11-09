// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"
#include "key.h"

/* Magic numbers for the EC key implementation structures */
static const uint64_t _PRIVATE_KEY_MAGIC = 0x19a751419ae04bbc;
static const uint64_t _PUBLIC_KEY_MAGIC = 0xb1d39580c1f14c02;

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

static oe_result_t _private_key_write_pem_callback(BIO* bio, EVP_PKEY* pkey)
{
    oe_result_t result = OE_UNEXPECTED;
    EC_KEY* ec = NULL;

    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
        OE_RAISE(OE_FAILURE);

    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    return result;
}

static oe_result_t _generate_key_pair(
    oe_ec_type_t ec_type,
    oe_private_key_t* private_key,
    oe_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    int nid;
    EC_KEY* ec_private = NULL;
    EC_KEY* ec_public = NULL;
    EVP_PKEY* pkey_private = NULL;
    EVP_PKEY* pkey_public = NULL;
    EC_POINT* point = NULL;

    if (private_key)
        oe_secure_zero_fill(private_key, sizeof(*private_key));

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_public_key_t));

    /* Check parameters */
    if (!private_key || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Get the NID for this curve type */
    if ((nid = _get_nid(ec_type)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the private EC key */
    {
        /* Create the private key */
        if (!(ec_private = EC_KEY_new_by_curve_name(nid)))
            OE_RAISE(OE_FAILURE);

        /* Set the EC named-curve flag */
        EC_KEY_set_asn1_flag(ec_private, OPENSSL_EC_NAMED_CURVE);

        /* Generate the public/private key pair */
        if (!EC_KEY_generate_key(ec_private))
            OE_RAISE(OE_FAILURE);
    }

    /* Create the public EC key */
    {
        /* Create the public key */
        if (!(ec_public = EC_KEY_new_by_curve_name(nid)))
            OE_RAISE(OE_FAILURE);

        /* Set the EC named-curve flag */
        EC_KEY_set_asn1_flag(ec_public, OPENSSL_EC_NAMED_CURVE);

        /* Duplicate public key point from the private key */
        if (!(point = EC_POINT_dup(
                  EC_KEY_get0_public_key(ec_private),
                  EC_KEY_get0_group(ec_public))))
        {
            OE_RAISE(OE_FAILURE);
        }

        /* Set the public key */
        if (!EC_KEY_set_public_key(ec_public, point))
            OE_RAISE(OE_FAILURE);

        /* Keep from being freed below */
        point = NULL;
    }

    /* Create the PKEY private key wrapper */
    {
        /* Create the private key structure */
        if (!(pkey_private = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the private key from the generated key pair */
        if (!EVP_PKEY_assign_EC_KEY(pkey_private, ec_private))
            OE_RAISE(OE_FAILURE);

        /* Initialize the private key */
        oe_private_key_init(private_key, pkey_private, _PRIVATE_KEY_MAGIC);

        /* Keep these from being freed below */
        ec_private = NULL;
        pkey_private = NULL;
    }

    /* Create the PKEY public key wrapper */
    {
        /* Create the public key structure */
        if (!(pkey_public = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key from the generated key pair */
        if (!EVP_PKEY_assign_EC_KEY(pkey_public, ec_public))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key */
        oe_public_key_init(public_key, pkey_public, _PUBLIC_KEY_MAGIC);

        /* Keep these from being freed below */
        ec_public = NULL;
        pkey_public = NULL;
    }

    result = OE_OK;

done:

    if (ec_private)
        EC_KEY_free(ec_private);

    if (ec_public)
        EC_KEY_free(ec_public);

    if (pkey_private)
        EVP_PKEY_free(pkey_private);

    if (pkey_public)
        EVP_PKEY_free(pkey_public);

    if (point)
        EC_POINT_free(point);

    if (result != OE_OK)
    {
        oe_private_key_free(private_key, _PRIVATE_KEY_MAGIC);
        oe_public_key_free(public_key, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

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
    if (!oe_public_key_is_valid(public_key1, _PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(public_key2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ec1 = EVP_PKEY_get1_EC_KEY(public_key1->pkey);
        ec2 = EVP_PKEY_get1_EC_KEY(public_key2->pkey);
        const EC_GROUP* group1 = EC_KEY_get0_group(ec1);
        const EC_GROUP* group2 = EC_KEY_get0_group(ec2);
        const EC_POINT* point1 = EC_KEY_get0_public_key(ec1);
        const EC_POINT* point2 = EC_KEY_get0_public_key(ec2);

        if (!ec1 || !ec2 || !group1 || !group2 || !point1 || !point2)
            OE_RAISE(OE_FAILURE);

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

void oe_ec_public_key_init(oe_ec_public_key_t* public_key, EVP_PKEY* pkey)
{
    return oe_public_key_init(
        (oe_public_key_t*)public_key, pkey, _PUBLIC_KEY_MAGIC);
}

void oe_ec_private_key_init(oe_ec_private_key_t* private_key, EVP_PKEY* pkey)
{
    return oe_private_key_init(
        (oe_private_key_t*)private_key, pkey, _PRIVATE_KEY_MAGIC);
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
        _PRIVATE_KEY_MAGIC);
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
        _PRIVATE_KEY_MAGIC);
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
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)private_key,
        pem_data,
        pem_size,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* private_key)
{
    return oe_private_key_free(
        (oe_private_key_t*)private_key, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key)
{
    return oe_public_key_free((oe_public_key_t*)public_key, _PUBLIC_KEY_MAGIC);
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
        _PRIVATE_KEY_MAGIC);
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
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_generate_key_pair(
    oe_ec_type_t type,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    return _generate_key_pair(
        type, (oe_private_key_t*)private_key, (oe_public_key_t*)public_key);
}

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

    /* Initialize OpenSSL. */
    oe_initialize_openssl();

    /* Initialize the EC key. */
    key = EC_KEY_new_by_curve_name(_get_nid(curve));
    if (key == NULL)
        OE_RAISE(OE_FAILURE);

    /* Set the EC named-curve flag. */
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    /* Load private key into the EC key. */
    private_bn = BN_bin2bn(private_key_buf, (int)private_key_buf_size, NULL);

    if (private_bn == NULL)
        OE_RAISE(OE_FAILURE);

    if (EC_KEY_set_private_key(key, private_bn) == 0)
        OE_RAISE(OE_FAILURE);

    public_point = EC_POINT_new(EC_KEY_get0_group(key));
    if (public_point == NULL)
        OE_RAISE(OE_FAILURE);

    /*
     * To get the public key, we perform the elliptical curve point
     * multiplication with the factors being the private key and the base
     * generator point of the curve.
     */
    openssl_result = EC_POINT_mul(
        EC_KEY_get0_group(key),
        public_point,
        private_bn,
        NULL,
        NULL,
        NULL);
    if (openssl_result == 0)
        OE_RAISE(OE_FAILURE);

    /* Sanity check the params. */
    if (EC_KEY_set_public_key(key, public_point) == 0)
        OE_RAISE(OE_FAILURE);

    if (EC_KEY_check_key(key) == 0)
        OE_RAISE(OE_FAILURE);

    /* Map the key to the EVP_PKEY wrapper. */
    public_pkey = EVP_PKEY_new();
    if (public_pkey == NULL)
        OE_RAISE(OE_FAILURE);

    if (EVP_PKEY_set1_EC_KEY(public_pkey, key) == 0)
        OE_RAISE(OE_FAILURE);

    private_pkey = EVP_PKEY_new();
    if (private_pkey == NULL)
        OE_RAISE(OE_FAILURE);

    if (EVP_PKEY_set1_EC_KEY(private_pkey, key) == 0)
        OE_RAISE(OE_FAILURE);

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


oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* public_key1,
    const oe_ec_public_key_t* public_key2,
    bool* equal)
{
    return _public_key_equal(
        (oe_public_key_t*)public_key1, (oe_public_key_t*)public_key2, equal);
}

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

    /* Initialize OpenSSL */
    oe_initialize_openssl();

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
            OE_RAISE(OE_FAILURE);

        if (!(ec = EC_KEY_new()))
            OE_RAISE(OE_FAILURE);

        if (!(EC_KEY_set_group(ec, group)))
            OE_RAISE(OE_FAILURE);

        if (!(point = EC_POINT_new(group)))
            OE_RAISE(OE_FAILURE);

        if (!(x = BN_new()) || !(y = BN_new()))
            OE_RAISE(OE_FAILURE);

        if (!(BN_bin2bn(x_data, (int)x_size, x)))
            OE_RAISE(OE_FAILURE);

        if (!(BN_bin2bn(y_data, (int)y_size, y)))
            OE_RAISE(OE_FAILURE);

        if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL))
            OE_RAISE(OE_FAILURE);

        if (!EC_KEY_set_public_key(ec, point))
            OE_RAISE(OE_FAILURE);

        point = NULL;
    }

    /* Create the PKEY public key wrapper */
    {
        /* Create the public key structure */
        if (!(pkey = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key from the generated key pair */
        {
            if (!EVP_PKEY_assign_EC_KEY(pkey, ec))
                OE_RAISE(OE_FAILURE);

            ec = NULL;
        }

        /* Initialize the public key */
        {
            oe_public_key_init(impl, pkey, _PUBLIC_KEY_MAGIC);
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

    /* Reject invalid parameters */
    if (!signature_size || !data || !size || size > OE_INT_MAX || !s_data ||
        !s_size || s_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature is null, then signature_size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create new signature object */
    if (!(sig = ECDSA_SIG_new()))
        OE_RAISE(OE_FAILURE);

    /* Convert R to big number object */
    if (!(BN_bin2bn(data, (int)size, sig->r)))
        OE_RAISE(OE_FAILURE);

    /* Convert S to big number object */
    if (!(BN_bin2bn(s_data, (int)s_size, sig->s)))
        OE_RAISE(OE_FAILURE);

    /* Determine the size of the binary signature */
    if ((sig_len = i2d_ECDSA_SIG(sig, NULL)) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Copy binary signature to output buffer */
    if (signature && ((size_t)sig_len <= *signature_size))
    {
        uint8_t* p = signature;

        if (!i2d_ECDSA_SIG(sig, &p))
            OE_RAISE(OE_FAILURE);

        if (p - signature != sig_len)
            OE_RAISE(OE_FAILURE);
    }

    /* Check whether buffer is too small */
    if ((size_t)sig_len > *signature_size)
    {
        *signature_size = (size_t)sig_len;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Set the size of the output buffer */
    *signature_size = (size_t)sig_len;

    result = OE_OK;

done:

    if (sig)
        ECDSA_SIG_free(sig);

    return result;
}
