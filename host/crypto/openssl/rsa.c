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

#if OPENSSL_VERSION_NUMBER < 0x30000000L
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
#else
oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* private_key_temp = (oe_private_key_t*)private_key;
    EVP_PKEY* rsa_public_pkey = NULL;
    const BIGNUM* public_e = NULL;
    const BIGNUM* public_n = NULL;

    /* Check for invalid parameters */
    if (!private_key || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    // RSA_get0_key(rsa_private, &public_e, &public_n, NULL);
    EVP_PKEY_get_bn_param(
        private_key_temp->pkey, OSSL_PKEY_PARAM_RSA_N, &public_n);
    EVP_PKEY_get_bn_param(
        private_key_temp->pkey, OSSL_PKEY_PARAM_RSA_E, &public_e);

    if (!public_e)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!public_n)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Init the OE public key type. */
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, public_n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, public_e);
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
        OE_RAISE(OE_CRYPTO_ERROR);
    if (!(rsa_public_pkey = EVP_PKEY_new()))
        OE_RAISE(OE_CRYPTO_ERROR);
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);
    if (EVP_PKEY_fromdata(ctx, &rsa_public_pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);
    oe_rsa_public_key_init(public_key, rsa_public_pkey);

    result = OE_OK;
    rsa_public_pkey = NULL;

done:
    if (rsa_public_pkey)
        EVP_PKEY_free(rsa_public_pkey);

    return result;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_rsa_public_key_from_modulus(
    const uint8_t* modulus,
    size_t modulus_size,
    const uint8_t* exponent,
    size_t exponent_size,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    BIGNUM *bignum_modulus = NULL, *bignum_exponent = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* pkey = NULL;

    if (!public_key || modulus_size > INT_MAX || exponent_size > INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    bignum_modulus = BN_bin2bn(modulus, (int)modulus_size, 0);
    bignum_exponent = BN_bin2bn(exponent, (int)exponent_size, 0);
    rsa = RSA_new();
    if (RSA_set0_key(rsa, bignum_modulus, bignum_exponent, NULL) != 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    pkey = EVP_PKEY_new();
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_rsa_public_key_init(public_key, pkey);

    result = OE_OK;

done:
    return result;
}
#else
oe_result_t oe_rsa_public_key_from_modulus(
    const uint8_t* modulus,
    size_t modulus_size,
    const uint8_t* exponent,
    size_t exponent_size,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    BIGNUM *bignum_modulus = NULL, *bignum_exponent = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* pkey = NULL;

    if (!public_key || modulus_size > INT_MAX || exponent_size > INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    bignum_modulus = BN_bin2bn(modulus, (int)modulus_size, 0);
    bignum_exponent = BN_bin2bn(exponent, (int)exponent_size, 0);

    pkey = EVP_PKEY_new();
    if ((EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, bignum_modulus) ==
         0) ||
        (EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, bignum_exponent) ==
         0))
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_rsa_public_key_init(public_key, pkey);

    result = OE_OK;

done:
    return result;
}
#endif
