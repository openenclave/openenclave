// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1
#include <openenclave/host.h>
#include <openenclave/internal/aesm.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/str.h>
#include <openenclave/internal/trace.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <time.h>
#include "../crypto/init.h"
#include "../host/enclave.h"

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
        OE_THROW(OE_INVALID_PARAMETER);

    t = time(NULL);

    if (localtime_r(&t, &tm) == NULL)
        OE_THROW(OE_FAILURE);

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
            b[i] = s[i] - '0';

        *date = (b[0] << 28) | (b[1] << 24) | (b[2] << 20) | (b[3] << 16) |
                (b[4] << 12) | (b[5] << 8) | (b[6] << 4) | b[7];
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _get_modulus(RSA* rsa, uint8_t modulus[OE_KEY_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_KEY_SIZE];

    if (!rsa || !modulus)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!BN_bn2bin(rsa->n, buf))
        OE_THROW(OE_FAILURE);

    _mem_reverse(modulus, buf, OE_KEY_SIZE);

    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _get_exponent(RSA* rsa, uint8_t exponent[OE_EXPONENT_SIZE])
{
    oe_result_t result = OE_UNEXPECTED;
    // uint8_t buf[OE_EXPONENT_SIZE];

    if (!rsa || !exponent)
        OE_THROW(OE_INVALID_PARAMETER);

    if (rsa->e->top != 1)
        OE_THROW(OE_FAILURE);

    {
        uint64_t x = rsa->e->d[0];
        exponent[0] = (x & 0x00000000000000FF) >> 0;
        exponent[1] = (x & 0x000000000000FF00) >> 8;
        exponent[2] = (x & 0x0000000000FF0000) >> 16;
        exponent[3] = (x & 0x00000000FF000000) >> 24;
    }

    result = OE_OK;

OE_CATCH:
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
    unsigned char q1buf[q1_out_size + 8];
    unsigned char q2buf[q2_out_size + 8];
    unsigned char sbuf[signature_size];
    unsigned char mbuf[modulus_size];

    if (!signature || !signature_size || !modulus || !modulus_size || !q1_out ||
        !q1_out_size || !q2_out || !q2_out_size)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    memset(sbuf, 0, sizeof(sbuf));
    memset(mbuf, 0, sizeof(mbuf));

    _mem_reverse(sbuf, signature, sizeof(sbuf));
    _mem_reverse(mbuf, modulus, sizeof(mbuf));

    /* Create new objects */
    {
        if (!(s = BN_bin2bn(sbuf, sizeof(sbuf), NULL)))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(m = BN_bin2bn(mbuf, sizeof(mbuf), NULL)))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(q1 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(q2 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(t1 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(t2 = BN_new()))
            OE_THROW(OE_OUT_OF_MEMORY);

        if (!(ctx = BN_CTX_new()))
            OE_THROW(OE_OUT_OF_MEMORY);
    }

    /* Perform arithmetic */
    {
        if (!BN_mul(t1, s, s, ctx))
            OE_THROW(OE_FAILURE);

        if (!BN_div(q1, t2, t1, m, ctx))
            OE_THROW(OE_FAILURE);

        if (!BN_mul(t1, s, t2, ctx))
            OE_THROW(OE_FAILURE);

        if (!BN_div(q2, t2, t1, m, ctx))
            OE_THROW(OE_FAILURE);
    }

    /* Copy Q1 to Q1OUT parameter */
    {
        size_t n = BN_num_bytes(q1);

        if (n > sizeof(q1buf))
            OE_THROW(OE_FAILURE);

        if (n > q1_out_size)
            n = q1_out_size;

        BN_bn2bin(q1, q1buf);
        _mem_reverse(q1_out, q1buf, n);
    }

    /* Copy Q2 to Q2OUT parameter */
    {
        size_t n = BN_num_bytes(q2);

        if (n > sizeof(q2buf))
            OE_THROW(OE_FAILURE);

        if (n > q2_out_size)
            n = q2_out_size;

        BN_bn2bin(q2, q2buf);
        _mem_reverse(q2_out, q2buf, n);
    }

    result = OE_OK;

OE_CATCH:

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

static oe_result_t _init_sigstruct(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    RSA* rsa,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!sigstruct)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-fill the structure */
    memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* sgx_sigstruct_t.header */
    memcpy(sigstruct->header, SGX_SIGSTRUCT_HEADER, sizeof(sigstruct->header));

    /* sgx_sigstruct_t.type */
    sigstruct->type = 0;

    /* sgx_sigstruct_t.vendor */
    sigstruct->vendor = 0;

    /* sgx_sigstruct_t.date */
    OE_TRY(_get_date(&sigstruct->date));

    /* sgx_sigstruct_t.header2 */
    memcpy(
        sigstruct->header2, SGX_SIGSTRUCT_HEADER2, sizeof(sigstruct->header2));

    /* sgx_sigstruct_t.swdefined */
    sigstruct->swdefined = 0;

    /* sgx_sigstruct_t.modulus */
    OE_TRY(_get_modulus(rsa, sigstruct->modulus));

    /* sgx_sigstruct_t.date */
    OE_TRY(_get_exponent(rsa, sigstruct->exponent));

    /* sgx_sigstruct_t.signature: fill in after other fields */

    /* sgx_sigstruct_t.miscselect */
    sigstruct->miscselect = SGX_SIGSTRUCT_MISCSELECT;

    /* sgx_sigstruct_t.miscmask */
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
    memcpy(sigstruct->enclavehash, mrenclave, sizeof(sigstruct->enclavehash));

    /* sgx_sigstruct_t.isvprodid */
    sigstruct->isvprodid = product_id;

    /* sgx_sigstruct_t.isvsvn */
    sigstruct->isvsvn = security_version;

    /* Sign header and body sections of SigStruct */
    {
        unsigned char buf[sizeof(sgx_sigstruct_t)];
        size_t n = 0;

        memcpy(
            buf, sgx_sigstruct_header(sigstruct), sgx_sigstruct_header_size());
        n += sgx_sigstruct_header_size();
        memcpy(
            &buf[n], sgx_sigstruct_body(sigstruct), sgx_sigstruct_body_size());
        n += sgx_sigstruct_body_size();

        {
            OE_SHA256 sha256;
            oe_sha256_context_t context;
            unsigned char signature[OE_KEY_SIZE];
            unsigned int signature_size;

            oe_sha256_init(&context);
            oe_sha256_update(&context, buf, n);
            oe_sha256_final(&context, &sha256);

            if (!RSA_sign(
                    NID_sha256,
                    sha256.buf,
                    sizeof(sha256),
                    signature,
                    &signature_size,
                    rsa))
            {
                OE_THROW(OE_FAILURE);
            }

            if (sizeof(sigstruct->signature) != signature_size)
                OE_THROW(OE_FAILURE);

            /* The signature is backwards and needs to be reversed */
            _mem_reverse(sigstruct->signature, signature, sizeof(signature));
        }
    }

    OE_TRY(
        _get_q1_and_q2(
            sigstruct->signature,
            sizeof(sigstruct->signature),
            sigstruct->modulus,
            sizeof(sigstruct->modulus),
            sigstruct->q1,
            sizeof(sigstruct->q1),
            sigstruct->q2,
            sizeof(sigstruct->q2)));

    result = OE_OK;

OE_CATCH:
    return result;
}

static oe_result_t _load_rsa_private_key(
    const uint8_t* pem_data,
    size_t pem_size,
    RSA** key)
{
    oe_result_t result = OE_UNEXPECTED;
    BIO* bio = NULL;
    RSA* rsa = NULL;

    if (key)
        *key = NULL;

    /* Check parameters */
    if (!pem_data || pem_size == 0 || !key)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pem_data, pem_size)))
        OE_THROW(OE_FAILURE);

    /* Read the RSA structure from the PEM data */
    if (!(rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL)))
        OE_THROW(OE_FAILURE);

    /* Set the output key parameter */
    *key = rsa;
    rsa = NULL;

    result = OE_OK;

OE_CATCH:

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_sgx_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const uint8_t* pem_data,
    size_t pem_size,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;
    RSA* rsa = NULL;

    if (sigstruct)
        memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* Check parameters */
    if (!mrenclave || !sigstruct)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Load the RSA private key from PEM */
    OE_TRY(_load_rsa_private_key(pem_data, pem_size, &rsa));

    /* Initialize the sigstruct */
    OE_TRY(
        _init_sigstruct(
            mrenclave,
            attributes,
            product_id,
            security_version,
            rsa,
            sigstruct));

    result = OE_OK;

OE_CATCH:

    if (rsa)
        RSA_free(rsa);

    return result;
}
