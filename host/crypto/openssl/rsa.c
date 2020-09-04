// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../../../common/crypto/openssl/rsa.h"
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "../../../common/crypto/openssl/key.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed for compatibility with ssl1.1 */

static void RSA_get0_key(
    const RSA* r,
    const BIGNUM** n,
    const BIGNUM** e,
    const BIGNUM** d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

static int RSA_set0_key(RSA* r, BIGNUM* n, BIGNUM* e, BIGNUM* d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL)
    {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL)
    {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL)
    {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

#endif

oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* private_key_temp = (oe_private_key_t*)private_key;
    RSA* rsa_private = NULL;
    RSA* rsa_public = NULL;
    EVP_PKEY* rsa_public_pkey = NULL;
    const BIGNUM* private_e = NULL;
    const BIGNUM* private_n = NULL;
    const BIGNUM* public_e = NULL;
    const BIGNUM* public_n = NULL;

    /* Check for invalid parameters */
    if (!private_key || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get RSA private key */
    if (!(rsa_private = EVP_PKEY_get1_RSA(private_key_temp->pkey)))
        OE_RAISE(OE_CRYPTO_ERROR);

    RSA_get0_key(rsa_private, &private_e, &private_n, NULL);

    /* Check if it's possible to get the public key. */
    if (!private_e || !private_n)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Create RSA public key. */
    if (!(rsa_public = RSA_new()))
        OE_RAISE(OE_CRYPTO_ERROR);

    RSA_get0_key(rsa_private, &public_e, &public_n, NULL);

    if (!public_e)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!public_n)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!RSA_set0_key(rsa_public, BN_dup(public_e), BN_dup(public_n), NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Init the OE public key type. */
    if (!(rsa_public_pkey = EVP_PKEY_new()))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (EVP_PKEY_set1_RSA(rsa_public_pkey, rsa_public) == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    oe_rsa_public_key_init(public_key, rsa_public_pkey);

    result = OE_OK;
    rsa_public_pkey = NULL;

done:
    if (rsa_public_pkey)
        EVP_PKEY_free(rsa_public_pkey);

    if (rsa_public)
        RSA_free(rsa_public);

    if (rsa_private)
        RSA_free(rsa_private);

    return result;
}

oe_result_t oe_rsa_public_key_from_modulus(
    const uint8_t* modulus,
    size_t modulus_size,
    const uint8_t* exponent,
    size_t exponent_size,
    oe_rsa_public_key_t* public_key)
{
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error OpenSSL 1.0.2 not supported
#endif
    oe_result_t result = OE_UNEXPECTED;
    BIGNUM *rm = NULL, *re = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* ikey = NULL;

    if (!public_key || modulus_size > INT_MAX || exponent_size > INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    rm = BN_bin2bn(modulus, (int)modulus_size, 0);
    re = BN_bin2bn(exponent, (int)exponent_size, 0);
    rsa = RSA_new();
    if (RSA_set0_key(rsa, rm, re, NULL) != 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    ikey = EVP_PKEY_new();
    if (EVP_PKEY_assign_RSA(ikey, rsa) != 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_rsa_public_key_init(public_key, ikey);

    result = OE_OK;

done:
    return result;
}