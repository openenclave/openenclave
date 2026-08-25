// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/localtime.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/str.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <time.h>
#include "enclave.h"

#include <openssl/bn.h>

static void _mem_reverse(void* dest_, const void* src_, size_t n)
{
    unsigned char* dest = (unsigned char*)dest_;
    const unsigned char* src = (const unsigned char*)src_;
    const unsigned char* end = src + n;

    while (n--)
        *dest++ = *--end;
}

static oe_result_t _get_date(unsigned int* date)
{
    oe_result_t result = OE_UNEXPECTED;
    time_t t;
    struct tm tm;
    size_t i;

    if (!date)
        OE_RAISE(OE_INVALID_PARAMETER);

    t = time(NULL);

    if (oe_localtime(&t, &tm))
        OE_RAISE(OE_FAILURE);

    {
        char s[9];
        unsigned char b[8];

        snprintf(
            s,
            sizeof(s),
            "%04u%02u%02u",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday);

        for (i = 0; i < sizeof(b); i++)
            b[i] = (unsigned char)(s[i] - '0');

        *date =
            (unsigned int)((b[0] << 28) | (b[1] << 24) | (b[2] << 20) | (b[3] << 16) | (b[4] << 12) | (b[5] << 8) | (b[6] << 4) | b[7]);
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_modulus(
    const oe_rsa_public_key_t* rsa,
    uint8_t modulus[OE_KEY_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_KEY_SIZE];
    size_t bufsize = sizeof(buf);

    if (!rsa || !modulus)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_get_modulus(rsa, buf, &bufsize));

    /* RSA key length is the modulus length, so these have to be equal. */
    if (bufsize != OE_KEY_SIZE)
        OE_RAISE(OE_FAILURE);

    _mem_reverse(modulus, buf, bufsize);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_exponent(
    const oe_rsa_public_key_t* rsa,
    uint8_t exponent[OE_EXPONENT_SIZE])
{
    static const uint8_t OE_SGX_SIGNING_EXPONENT[] = {3, 0, 0, 0};
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_EXPONENT_SIZE];
    size_t bufsize = sizeof(buf);

    if (!rsa || !exponent)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_get_exponent(rsa, buf, &bufsize));

    /* Exponent is in big endian. So, we need to reverse. */
    _mem_reverse(exponent, buf, bufsize);

    /* We zero out the rest to get the right exponent in little endian. */
    OE_CHECK(oe_memset_s(
        exponent + bufsize,
        OE_EXPONENT_SIZE - bufsize,
        0,
        OE_EXPONENT_SIZE - bufsize));

    /* Check that the exponent matches SGX requirement */
    if (memcmp(OE_SGX_SIGNING_EXPONENT, exponent, OE_EXPONENT_SIZE) != 0)
        OE_RAISE(OE_INVALID_SGX_SIGNING_KEY);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_q1_and_q2(
    const void* signature,
    size_t signature_size,
    const void* modulus,
    size_t modulus_size,
    void* q1_out,
    size_t q1_out_size,
    void* q2_out,
    size_t q2_out_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BIGNUM* s = NULL;
    BIGNUM* m = NULL;
    BIGNUM* q1 = NULL;
    BIGNUM* q2 = NULL;
    BIGNUM* t1 = NULL;
    BIGNUM* t2 = NULL;
    BN_CTX* ctx = NULL;
    unsigned char q1buf[OE_KEY_SIZE + 8];
    unsigned char q2buf[OE_KEY_SIZE + 8];
    unsigned char sbuf[OE_KEY_SIZE];
    unsigned char mbuf[OE_KEY_SIZE];

    if (!signature || !signature_size || !modulus || !modulus_size || !q1_out ||
        !q1_out_size || !q2_out || !q2_out_size ||
        signature_size > sizeof(sbuf) || modulus_size > sizeof(mbuf) ||
        q1_out_size > OE_KEY_SIZE || q2_out_size > OE_KEY_SIZE)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    _mem_reverse(sbuf, signature, signature_size);
    _mem_reverse(mbuf, modulus, modulus_size);

    /* Create new objects */
    {
        if (!(s = BN_bin2bn(sbuf, (int)signature_size, NULL)))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if (!(m = BN_bin2bn(mbuf, (int)modulus_size, NULL)))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if (!(q1 = BN_new()))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if (!(q2 = BN_new()))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if (!(t1 = BN_new()))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if (!(t2 = BN_new()))
            OE_RAISE(OE_OUT_OF_MEMORY);

        if (!(ctx = BN_CTX_new()))
            OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Perform arithmetic */
    {
        if (!BN_mul(t1, s, s, ctx))
            OE_RAISE(OE_FAILURE);

        if (!BN_div(q1, t2, t1, m, ctx))
            OE_RAISE(OE_FAILURE);

        if (!BN_mul(t1, s, t2, ctx))
            OE_RAISE(OE_FAILURE);

        if (!BN_div(q2, t2, t1, m, ctx))
            OE_RAISE(OE_FAILURE);
    }

    /* Copy Q1 to Q1OUT parameter */
    {
        size_t n = (size_t)BN_num_bytes(q1);

        if (n > sizeof(q1buf))
            OE_RAISE(OE_FAILURE);

        if (n > q1_out_size)
            n = q1_out_size;

        BN_bn2bin(q1, q1buf);
        _mem_reverse(q1_out, q1buf, n);
    }

    /* Copy Q2 to Q2OUT parameter */
    {
        size_t n = (size_t)BN_num_bytes(q2);

        if (n > sizeof(q2buf))
            OE_RAISE(OE_FAILURE);

        if (n > q2_out_size)
            n = q2_out_size;

        BN_bn2bin(q2, q2buf);
        _mem_reverse(q2_out, q2buf, n);
    }

    result = OE_OK;

done:
    if (s)
        BN_free(s);
    if (m)
        BN_free(m);
    if (q1)
        BN_free(q1);
    if (q2)
        BN_free(q2);
    if (t1)
        BN_free(t1);
    if (t2)
        BN_free(t2);
    if (ctx)
        BN_CTX_free(ctx);

    return result;
}

static oe_result_t _hash_sigstruct(
    const sgx_sigstruct_t* sigstruct,
    OE_SHA256* hash)
{
    oe_result_t result = OE_UNEXPECTED;
    unsigned char buf[sizeof(sgx_sigstruct_t)];
    size_t buf_size = 0;

    /* Note that the sigstruct header and body sections are non-contiguous
     * and are copied into a single buffer to be hashed as defined by SGX */
    OE_CHECK(oe_memcpy_s(
        buf,
        sizeof(buf),
        sgx_sigstruct_header(sigstruct),
        sgx_sigstruct_header_size()));
    buf_size += sgx_sigstruct_header_size();

    OE_CHECK(oe_memcpy_s(
        &buf[buf_size],
        sizeof(buf) - buf_size,
        sgx_sigstruct_body(sigstruct),
        sgx_sigstruct_body_size()));
    buf_size += sgx_sigstruct_body_size();

    OE_CHECK(oe_sha256(buf, buf_size, hash));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _digest_sign_sigstruct(
    const oe_rsa_public_key_t* rsa,
    const uint8_t* digest_signature,
    size_t digest_signature_size,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_SHA256 digest = {0};

    /* sgx_sigstruct_t.modulus */
    OE_CHECK(_get_modulus(rsa, sigstruct->modulus));

    /* sgx_sigstruct_t.exponent */
    OE_CHECK(_get_exponent(rsa, sigstruct->exponent));

    /* sgx_sigstruct_t.signature */
    OE_CHECK(_hash_sigstruct(sigstruct, &digest));

    /* The signature is backwards and needs to be reversed */
    _mem_reverse(sigstruct->signature, digest_signature, digest_signature_size);

    /* sgx_sigstruct_t.q1 and q2 */
    OE_CHECK(_get_q1_and_q2(
        sigstruct->signature,
        sizeof(sigstruct->signature),
        sigstruct->modulus,
        sizeof(sigstruct->modulus),
        sigstruct->q1,
        sizeof(sigstruct->q1),
        sigstruct->q2,
        sizeof(sigstruct->q2)));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sign_sigstruct(
    const oe_rsa_private_key_t* rsa,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_rsa_public_key_t rsa_public;
    bool key_initialized = false;

    OE_CHECK(oe_rsa_get_public_key_from_private(rsa, &rsa_public));
    key_initialized = true;

    /* sgx_sigstruct_t.modulus */
    OE_CHECK(_get_modulus(&rsa_public, sigstruct->modulus));

    /* sgx_sigstruct_t.exponent */
    OE_CHECK(_get_exponent(&rsa_public, sigstruct->exponent));

    /* sgx_sigstruct_t.signature */
    {
        OE_SHA256 sha256;
        unsigned char signature[OE_KEY_SIZE];
        size_t signature_size = sizeof(signature);

        OE_CHECK(_hash_sigstruct(sigstruct, &sha256));

        OE_CHECK(oe_rsa_private_key_sign(
            rsa,
            OE_HASH_TYPE_SHA256,
            sha256.buf,
            sizeof(sha256),
            signature,
            &signature_size));

        if (sizeof(sigstruct->signature) != signature_size)
            OE_RAISE(OE_FAILURE);

        /* The signature is backwards and needs to be reversed */
        _mem_reverse(sigstruct->signature, signature, sizeof(signature));
    }

    /* sgx_sigstruct_t.q1 and q2 */
    OE_CHECK(_get_q1_and_q2(
        sigstruct->signature,
        sizeof(sigstruct->signature),
        sigstruct->modulus,
        sizeof(sigstruct->modulus),
        sigstruct->q1,
        sizeof(sigstruct->q1),
        sigstruct->q2,
        sizeof(sigstruct->q2)));

    result = OE_OK;

done:
    if (key_initialized)
        oe_rsa_public_key_free(&rsa_public);

    return result;
}

static oe_result_t _init_sigstruct(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const oe_sgx_enclave_flags_t* flags,
    const uint8_t* family_id,
    const uint8_t* extended_product_id,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!sigstruct)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Zero-fill the structure */
    memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* sgx_sigstruct_t.header */
    OE_CHECK(oe_memcpy_s(
        sigstruct->header,
        sizeof(sigstruct->header),
        SGX_SIGSTRUCT_HEADER,
        SGX_SIGSTRUCT_HEADER_SIZE));

    /* sgx_sigstruct_t.type */
    sigstruct->type = 0;

    /* sgx_sigstruct_t.vendor */
    sigstruct->vendor = 0;

    /* sgx_sigstruct_t.date */
    OE_CHECK(_get_date(&sigstruct->date));

    /* sgx_sigstruct_t.header2 */
    OE_CHECK(oe_memcpy_s(
        sigstruct->header2,
        sizeof(sigstruct->header2),
        SGX_SIGSTRUCT_HEADER2,
        SGX_SIGSTRUCT_HEADER2_SIZE));

    /* sgx_sigstruct_t.swdefined */
    sigstruct->swdefined = 0;

    /*
     * Skip signature fields:
     * sgx_sigstruct_t.modulus
     * sgx_sigstruct_t.exponent
     * sgx_sigstruct_t.signature
     */

    /* sgx_sigstruct_t.miscselect */
    sigstruct->miscselect = SGX_SIGSTRUCT_MISCSELECT;

    /* sgx_sigstruct_t.miscmask */
    if (flags && flags->capture_pf_gp_exceptions)
        sigstruct->miscmask = SGX_SIGSTRUCT_MISCMASK_EXINFO;
    else
        sigstruct->miscmask = SGX_SIGSTRUCT_MISCMASK;

    /* sgx_sigstruct_t.attributes */
    sigstruct->attributes.flags = attributes;
    sigstruct->attributes.xfrm = SGX_ATTRIBUTES_DEFAULT_XFRM;

    /* sgx_sigstruct_t.attributemask */
    sigstruct->attributemask.flags = SGX_SIGSTRUCT_ATTRIBUTEMASK_FLAGS;
    sigstruct->attributemask.xfrm = SGX_SIGSTRUCT_ATTRIBUTEMASK_XFRM;

    /* In debug enclaves, we don't care about the debug bit, so unmask it. */
    if (attributes & SGX_FLAGS_DEBUG)
        sigstruct->attributemask.flags &= ~SGX_FLAGS_DEBUG;

    /* sgx_sigstruct_t.enclavehash */
    OE_CHECK(oe_memcpy_s(
        sigstruct->enclavehash,
        sizeof(sigstruct->enclavehash),
        mrenclave,
        sizeof(*mrenclave)));

    if (attributes & SGX_FLAGS_KSS)
    {
        if (family_id)
            OE_CHECK(oe_memcpy_s(
                sigstruct->isvfamilyid,
                sizeof(sigstruct->isvfamilyid),
                family_id,
                sizeof(sigstruct->isvfamilyid)));
        if (extended_product_id)
            OE_CHECK(oe_memcpy_s(
                sigstruct->isvextprodid,
                sizeof(sigstruct->isvextprodid),
                extended_product_id,
                sizeof(sigstruct->isvextprodid)));
        sigstruct->attributemask.flags |= SGX_FLAGS_KSS;
    }

    /* sgx_sigstruct_t.isvprodid */
    sigstruct->isvprodid = product_id;

    /* sgx_sigstruct_t.isvsvn */
    sigstruct->isvsvn = security_version;

    /*
     * Skip signature fields:
     * sgx_sigstruct_t.q1
     * sgx_sigstruct_t.q2
     */

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_sign_enclave_from_engine(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const oe_sgx_enclave_flags_t* flags,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id,
    const uint8_t* family_id,
    const uint8_t* extended_product_id,
    sgx_sigstruct_t* sigstruct)
{
    oe_rsa_private_key_t rsa;
    bool rsa_initalized = false;
    oe_result_t result = OE_UNEXPECTED;

    /* Check parameters */
    if (!mrenclave || !sigstruct || !engine_id || !key_id)
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* Load the RSA private key from the specified engine */
    OE_CHECK(oe_rsa_private_key_from_engine(
        &rsa, engine_id, engine_load_path, key_id));
    rsa_initalized = true;

    /* Initialize & sign the sigstruct */
    OE_CHECK(_init_sigstruct(
        mrenclave,
        attributes,
        product_id,
        security_version,
        flags,
        family_id,
        extended_product_id,
        sigstruct));
    OE_CHECK(_sign_sigstruct(&rsa, sigstruct));

    result = OE_OK;

done:
    if (rsa_initalized)
        oe_rsa_private_key_free(&rsa);

    return result;
}

oe_result_t oe_sgx_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const oe_sgx_enclave_flags_t* flags,
    const uint8_t* pem_data,
    size_t pem_size,
    const uint8_t* family_id,
    const uint8_t* extended_product_id,
    sgx_sigstruct_t* sigstruct)
{
    oe_rsa_private_key_t rsa;
    bool rsa_initalized = false;
    oe_result_t result = OE_UNEXPECTED;

    if (sigstruct)
        memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* Check parameters */
    if (!mrenclave || !sigstruct || !pem_data)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the RSA private key from PEM */
    OE_CHECK(oe_rsa_private_key_read_pem(&rsa, pem_data, pem_size));
    rsa_initalized = true;

    /* Initialize & sign the sigstruct */
    OE_CHECK(_init_sigstruct(
        mrenclave,
        attributes,
        product_id,
        security_version,
        flags,
        family_id,
        extended_product_id,
        sigstruct));
    OE_CHECK(_sign_sigstruct(&rsa, sigstruct));

    result = OE_OK;

done:
    if (rsa_initalized)
        oe_rsa_private_key_free(&rsa);

    return result;
}

oe_result_t oe_sgx_get_sigstruct_digest(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const oe_sgx_enclave_flags_t* flags,
    const uint8_t* family_id,
    const uint8_t* extended_product_id,
    OE_SHA256* digest)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_sigstruct_t sigstruct;

    if (digest)
        memset(digest, 0, sizeof(OE_SHA256));

    /* Check parameters */
    if (!mrenclave || !digest)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize & sign the sigstruct */
    OE_CHECK(_init_sigstruct(
        mrenclave,
        attributes,
        product_id,
        security_version,
        flags,
        family_id,
        extended_product_id,
        &sigstruct));
    OE_CHECK(_hash_sigstruct(&sigstruct, digest));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_digest_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const oe_sgx_enclave_flags_t* flags,
    const uint8_t* cert_pem_data,
    size_t cert_pem_size,
    const uint8_t* digest_signature,
    size_t digest_signature_size,
    const uint8_t* family_id,
    const uint8_t* extended_product_id,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_cert_t cert = {0};
    bool cert_initialized = false;
    oe_rsa_public_key_t rsa = {0};
    bool rsa_initalized = false;
    OE_SHA256 digest = {0};

    if (sigstruct)
        memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* Check parameters */
    if (!mrenclave || !sigstruct || !cert_pem_data)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the RSA public key from x509 PEM certificate */
    OE_CHECK(oe_cert_read_pem(&cert, cert_pem_data, cert_pem_size));
    cert_initialized = true;

    OE_CHECK(oe_cert_get_rsa_public_key(&cert, &rsa));
    rsa_initalized = true;

    /* Initialize the sigstruct with the provided parameters */
    OE_CHECK(_init_sigstruct(
        mrenclave,
        attributes,
        product_id,
        security_version,
        flags,
        family_id,
        extended_product_id,
        sigstruct));

    /* Verify that the digest of the resulting sigstruct still
     * matches the expected signature */
    OE_CHECK(_hash_sigstruct(sigstruct, &digest));

    OE_CHECK(oe_rsa_public_key_verify(
        &rsa,
        OE_HASH_TYPE_SHA256,
        digest.buf,
        sizeof(digest.buf),
        digest_signature,
        digest_signature_size));

    /* Sign the verified sigstruct with the provided signature */
    OE_CHECK(_digest_sign_sigstruct(
        &rsa, digest_signature, digest_signature_size, sigstruct));

    result = OE_OK;

done:
    if (rsa_initalized)
        oe_rsa_public_key_free(&rsa);

    if (cert_initialized)
        oe_cert_free(&cert);

    return result;
}
