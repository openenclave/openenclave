// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/signsgx.h>
#include <openenclave/bits/str.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <time.h>
#include "../host/enclave.h"

static void _MemReverse(void* dest_, const void* src_, size_t n)
{
    unsigned char* dest = (unsigned char*)dest_;
    const unsigned char* src = (const unsigned char*)src_;
    const unsigned char* end = src + n;

    while (n--)
        *dest++ = *--end;
}

static OE_Result _GetDate(unsigned int* date)
{
    OE_Result result = OE_UNEXPECTED;
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

static OE_Result _GetModulus(RSA* rsa, uint8_t modulus[OE_KEY_SIZE])
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buf[OE_KEY_SIZE];

    if (!rsa || !modulus)
        OE_THROW(OE_INVALID_PARAMETER);

    if (!BN_bn2bin(rsa->n, buf))
        OE_THROW(OE_FAILURE);

    _MemReverse(modulus, buf, OE_KEY_SIZE);

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _GetExponent(RSA* rsa, uint8_t exponent[OE_EXPONENT_SIZE])
{
    OE_Result result = OE_UNEXPECTED;
    // uint8_t buf[OE_EXPONENT_SIZE];

    if (!rsa || !exponent)
        OE_THROW(OE_INVALID_PARAMETER);

    if (rsa->e->top != 1)
        OE_THROW(OE_FAILURE);

    {
        unsigned long long x = rsa->e->d[0];
        exponent[0] = (x & 0x00000000000000FF) >> 0;
        exponent[1] = (x & 0x000000000000FF00) >> 8;
        exponent[2] = (x & 0x0000000000FF0000) >> 16;
        exponent[3] = (x & 0x00000000FF000000) >> 24;
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _GetQ1AndQ2(
    const void* signature,
    size_t signatureSize,
    const void* modulus,
    size_t modulusSize,
    void* q1Out,
    size_t q1OutSize,
    void* q2Out,
    size_t q2OutSize)
{
    OE_Result result = OE_UNEXPECTED;
    BIGNUM* s = NULL;
    BIGNUM* m = NULL;
    BIGNUM* q1 = NULL;
    BIGNUM* q2 = NULL;
    BIGNUM* t1 = NULL;
    BIGNUM* t2 = NULL;
    BN_CTX* ctx = NULL;
    unsigned char q1buf[q1OutSize + 8];
    unsigned char q2buf[q2OutSize + 8];
    unsigned char sbuf[signatureSize];
    unsigned char mbuf[modulusSize];

    if (!signature || !signatureSize || !modulus || !modulusSize || !q1Out ||
        !q1OutSize || !q2Out || !q2OutSize)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    memset(sbuf, 0, sizeof(sbuf));
    memset(mbuf, 0, sizeof(mbuf));

    _MemReverse(sbuf, signature, sizeof(sbuf));
    _MemReverse(mbuf, modulus, sizeof(mbuf));

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

        if (n > q1OutSize)
            n = q1OutSize;

        BN_bn2bin(q1, q1buf);
        _MemReverse(q1Out, q1buf, n);
    }

    /* Copy Q2 to Q2OUT parameter */
    {
        size_t n = BN_num_bytes(q2);

        if (n > sizeof(q2buf))
            OE_THROW(OE_FAILURE);

        if (n > q2OutSize)
            n = q2OutSize;

        BN_bn2bin(q2, q2buf);
        _MemReverse(q2Out, q2buf, n);
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

static OE_Result _InitSigstruct(
    const OE_SHA256* mrenclave,
    uint16_t productID,
    uint16_t securityVersion,
    RSA* rsa,
    SGX_SigStruct* sigstruct)
{
    OE_Result result = OE_UNEXPECTED;

    if (!sigstruct)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Zero-fill the structure */
    memset(sigstruct, 0, sizeof(SGX_SigStruct));

    /* SGX_SigStruct.header */
    memcpy(sigstruct->header, SGX_SIGSTRUCT_HEADER, sizeof(sigstruct->header));

    /* SGX_SigStruct.type */
    sigstruct->type = 0;

    /* SGX_SigStruct.vendor */
    sigstruct->vendor = 0;

    /* SGX_SigStruct.date */
    OE_TRY(_GetDate(&sigstruct->date));

    /* SGX_SigStruct.header2 */
    memcpy(
        sigstruct->header2, SGX_SIGSTRUCT_HEADER2, sizeof(sigstruct->header2));

    /* SGX_SigStruct.swdefined */
    sigstruct->swdefined = 0;

    /* SGX_SigStruct.modulus */
    OE_TRY(_GetModulus(rsa, sigstruct->modulus));

    /* SGX_SigStruct.date */
    OE_TRY(_GetExponent(rsa, sigstruct->exponent));

    /* SGX_SigStruct.signature: fill in after other fields */

    /* SGX_SigStruct.miscselect */
    sigstruct->miscselect = SGX_SIGSTRUCT_MISCSELECT;

    /* SGX_SigStruct.miscmask */
    sigstruct->miscmask = SGX_SIGSTRUCT_MISCMASK;

    /* SGX_SigStruct.attributes */
    sigstruct->attributes.flags = SGX_ATTRIBUTES_DEFAULT_FLAGS;
    sigstruct->attributes.xfrm = SGX_ATTRIBUTES_DEFAULT_XFRM;

    /* SGX_SigStruct.attributemask */
    sigstruct->attributemask.flags = SGX_SIGSTRUCT_ATTRIBUTEMASK_FLAGS;
    sigstruct->attributemask.xfrm = SGX_SIGSTRUCT_ATTRIBUTEMASK_XFRM;

    /* SGX_SigStruct.enclavehash */
    memcpy(sigstruct->enclavehash, mrenclave, sizeof(sigstruct->enclavehash));

    /* SGX_SigStruct.isvprodid */
    sigstruct->isvprodid = productID;

    /* SGX_SigStruct.isvsvn */
    sigstruct->isvsvn = securityVersion;

    /* Sign header and body sections of SigStruct */
    {
        unsigned char buf[sizeof(SGX_SigStruct)];
        size_t n = 0;

        memcpy(buf, SGX_SigStructHeader(sigstruct), SGX_SigStructHeaderSize());
        n += SGX_SigStructHeaderSize();
        memcpy(&buf[n], SGX_SigStructBody(sigstruct), SGX_SigStructBodySize());
        n += SGX_SigStructBodySize();

        {
            OE_SHA256 sha256;
            OE_SHA256Context context;
            unsigned char signature[OE_KEY_SIZE];
            unsigned int signatureSize;

            OE_SHA256Init(&context);
            OE_SHA256Update(&context, buf, n);
            OE_SHA256Final(&context, &sha256);

            if (!RSA_sign(
                    NID_sha256,
                    sha256.buf,
                    sizeof(sha256),
                    signature,
                    &signatureSize,
                    rsa))
            {
                OE_THROW(OE_FAILURE);
            }

            if (sizeof(sigstruct->signature) != signatureSize)
                OE_THROW(OE_FAILURE);

            /* The signature is backwards and needs to be reversed */
            _MemReverse(sigstruct->signature, signature, sizeof(signature));
        }
    }

    OE_TRY(
        _GetQ1AndQ2(
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

static void _InitializeOpenSSL(void)
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}

static OE_Result _LoadRSAPrivateKey(
    const char* pemData,
    size_t pemSize,
    RSA** key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    RSA* rsa = NULL;

    if (key)
        *key = NULL;

    /* Check parameters */
    if (!pemData || pemSize == 0 || !key)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    _InitializeOpenSSL();

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
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

OE_Result OE_SignEnclave_SGX(
    const OE_SHA256* mrenclave,
    uint16_t productID,
    uint16_t securityVersion,
    const char* pemData,
    size_t pemSize,
    SGX_SigStruct* sigstruct)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = NULL;

    if (sigstruct)
        memset(sigstruct, 0, sizeof(SGX_SigStruct));

    /* Check parameters */
    if (!mrenclave || !sigstruct)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Load the RSA private key from PEM */
    OE_TRY(_LoadRSAPrivateKey(pemData, pemSize, &rsa));

    /* Initialize the sigstruct */
    OE_TRY(
        _InitSigstruct(mrenclave, productID, securityVersion, rsa, sigstruct));

    result = OE_OK;

OE_CATCH:

    if (rsa)
        RSA_free(rsa);

    return result;
}
