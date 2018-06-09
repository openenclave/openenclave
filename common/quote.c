// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "quote.h"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sha.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include <stdio.h>

#ifdef OE_USE_LIBSGX

// Public key of Intel's root certificate.
static const char* g_ExpectedRootCertificateKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
    "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
    "-----END PUBLIC KEY-----\n";

// The mrsigner value of Intel's Production quoting enclave.
static const uint8_t g_QEMrSigner[32] = {
    0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f,
    0x77, 0xc6, 0x8a, 0x82, 0x9a, 0x00, 0x56, 0xac, 0x8d, 0xed, 0x70,
    0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff};

// The isvprodid value of Intel's Production quoting enclave.
static const uint32_t g_QEISVProdId = 1;

// The isvsvn value of Intel's Production quoting enclave.
static const uint32_t g_QEISVSVN = 1;

OE_INLINE uint16_t ReadUint16(const uint8_t* p)
{
    return p[0] | (p[1] << 8);
}

OE_INLINE uint32_t ReadUint32(const uint8_t* p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static OE_Result _ParseQuote(
    const uint8_t* quote,
    uint32_t quoteSize,
    SGX_Quote** sgxQuote,
    SGX_QuoteAuthData** quoteAuthData,
    SGX_QEAuthData* qeAuthData,
    SGX_QECertData* qeCertData)
{
    OE_Result result = OE_UNEXPECTED;

    const uint8_t* p = quote;
    const uint8_t* const quoteEnd = quote + quoteSize;

    if (quoteEnd < p)
    {
        // Pointer wrapped around.
        OE_RAISE(OE_QUOTE_PARSE_ERROR);
    }

    *sgxQuote = NULL;

    *sgxQuote = (SGX_Quote*)p;
    p += sizeof(SGX_Quote);
    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    if (p + (*sgxQuote)->signature_len != quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    *quoteAuthData = (SGX_QuoteAuthData*)(*sgxQuote)->signature;
    p += sizeof(SGX_QuoteAuthData);

    qeAuthData->size = ReadUint16(p);
    p += 2;
    qeAuthData->data = (uint8_t*)p;
    p += qeAuthData->size;

    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    qeCertData->type = ReadUint16(p);
    p += 2;
    qeCertData->size = ReadUint32(p);
    p += 4;
    qeCertData->data = (uint8_t*)p;
    p += qeCertData->size;

    if (p != quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    result = OE_OK;
done:
    return result;
}

static OE_Result _ReadPublicKey(SGX_ECDSA256Key* key, OE_ECPublicKey* publicKey)
{
    return OE_ECPublicKeyFromCoordinates(
        publicKey,
        OE_EC_TYPE_SECP256R1,
        key->x,
        sizeof(key->x),
        key->y,
        sizeof(key->y));
}

static OE_Result _ECDSAVerify(
    OE_ECPublicKey* publicKey,
    void* data,
    uint32_t dataSize,
    SGX_ECDSA256Signature* signature)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SHA256Context sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t asn1Signature[256];
    uint64_t asn1SignatureSize = sizeof(asn1Signature);

    OE_CHECK(OE_SHA256Init(&sha256Ctx));
    OE_CHECK(OE_SHA256Update(&sha256Ctx, data, dataSize));
    OE_CHECK(OE_SHA256Final(&sha256Ctx, &sha256));

    OE_CHECK(
        OE_ECDSASignatureWriteDER(
            asn1Signature,
            &asn1SignatureSize,
            signature->r,
            sizeof(signature->r),
            signature->s,
            sizeof(signature->s)));

    OE_CHECK(
        OE_ECPublicKeyVerify(
            publicKey,
            OE_HASH_TYPE_SHA256,
            (uint8_t*)&sha256,
            sizeof(sha256),
            asn1Signature,
            asn1SignatureSize));

    result = OE_OK;
done:
    return result;
}

OE_Result VerifyQuoteImpl(
    const uint8_t* quote,
    uint32_t quoteSize,
    const uint8_t* pemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* pckCrl,
    uint32_t pckCrlSize,
    const uint8_t* tcbInfoJson,
    uint32_t tcbInfoJsonSize)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_Quote* sgxQuote = NULL;
    SGX_QuoteAuthData* quoteAuthData = NULL;
    SGX_QEAuthData qeAuthData = {0};
    SGX_QECertData qeCertData = {0};
    OE_CertChain pckCertChain = {0};
    OE_SHA256Context sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    OE_ECPublicKey attestationKey = {0};
    uint64_t numCerts = 0;
    OE_Cert leafCert = {0};
    OE_Cert rootCert = {0};
    OE_ECPublicKey leafPublicKey = {0};
    OE_ECPublicKey rootPublicKey = {0};
    OE_ECPublicKey expectedRootPublicKey = {0};
    bool keyEqual = false;

    OE_CHECK(
        _ParseQuote(
            quote,
            quoteSize,
            &sgxQuote,
            &quoteAuthData,
            &qeAuthData,
            &qeCertData));

    if (sgxQuote->version != OE_SGX_QUOTE_VERSION)
    {
        OE_RAISE(OE_VERIFY_FAILED);
    }

    // The certificate provided in the quote is preferred.
    if (qeCertData.type == OE_SGX_PCK_ID_PCK_CERT_CHAIN)
    {
        if (qeCertData.size == 0)
            OE_RAISE(OE_FAILURE);
        pemPckCertificate = qeCertData.data;
        pemPckCertificateSize = qeCertData.size;
    }
    else
    {
        OE_RAISE(OE_UNSUPPORTED_QE_CERTIFICATION);
    }

    if (pemPckCertificate == NULL)
        OE_RAISE(OE_UNSUPPORTED_QE_CERTIFICATION);

    // PckCertificate Chain validations.
    {
        // Read and validate the chain.
        OE_CHECK(
            OE_CertChainReadPEM(
                pemPckCertificate, pemPckCertificateSize, &pckCertChain));

        // Fetch leaf and root certificates.
        // TODO: Use appropriate cert methods when available.
        OE_CHECK(OE_CertChainGetCert(&pckCertChain, 0, &leafCert));

        OE_CHECK(OE_CertChainGetLength(&pckCertChain, &numCerts));
        OE_CHECK(OE_CertChainGetCert(&pckCertChain, numCerts - 1, &rootCert));

        OE_CHECK(OE_CertGetECPublicKey(&leafCert, &leafPublicKey));
        OE_CHECK(OE_CertGetECPublicKey(&rootCert, &rootPublicKey));

        // Ensure that the root certificate matches root of trust.
        OE_CHECK(
            OE_ECPublicKeyReadPEM(
                (const uint8_t*)g_ExpectedRootCertificateKey,
                OE_Strlen(g_ExpectedRootCertificateKey) + 1,
                &expectedRootPublicKey));

        OE_CHECK(
            OE_ECPublicKeyEqual(
                &rootPublicKey, &expectedRootPublicKey, &keyEqual));
        if (!keyEqual)
            OE_RAISE(OE_VERIFY_FAILED);
    }

    // Quote validations.
    {
        // Verify SHA256 ECDSA (qeReportBodySignature, qeReportBody,
        // PckCertificate.pubKey)
        OE_CHECK(
            _ECDSAVerify(
                &leafPublicKey,
                &quoteAuthData->qeReportBody,
                sizeof(quoteAuthData->qeReportBody),
                &quoteAuthData->qeReportBodySignature));

        // Assert SHA256 (attestationKey + qeAuthData.data) ==
        // qeReportBody.reportData[0..32]
        OE_CHECK(OE_SHA256Init(&sha256Ctx));
        OE_CHECK(
            OE_SHA256Update(
                &sha256Ctx,
                (const uint8_t*)&quoteAuthData->attestationKey,
                sizeof(quoteAuthData->attestationKey)));
        if (qeAuthData.size > 0)
        {
            OE_CHECK(
                OE_SHA256Update(&sha256Ctx, qeAuthData.data, qeAuthData.size));
        }
        OE_CHECK(OE_SHA256Final(&sha256Ctx, &sha256));

        if (!OE_ConstantTimeMemEqual(
                &sha256,
                &quoteAuthData->qeReportBody.reportData,
                sizeof(sha256)))
            OE_RAISE(OE_VERIFY_FAILED);

        // Verify SHA256 ECDSA (attestationKey, SGX_QUOTE_SIGNED_DATA,
        // signature)
        OE_CHECK(
            _ReadPublicKey(&quoteAuthData->attestationKey, &attestationKey));

        OE_CHECK(
            _ECDSAVerify(
                &attestationKey,
                sgxQuote,
                SGX_QUOTE_SIGNED_DATA_SIZE,
                &quoteAuthData->signature));
    }

    // Quoting Enclave validations.
    {
        // Assert that the qe report's mr signer matches Intel's quoting
        // enclave's mrsigner.
        if (!OE_ConstantTimeMemEqual(
                quoteAuthData->qeReportBody.mrsigner,
                g_QEMrSigner,
                sizeof(g_QEMrSigner)))
            OE_RAISE(OE_VERIFY_FAILED);

        if (quoteAuthData->qeReportBody.isvprodid != g_QEISVProdId)
            OE_RAISE(OE_VERIFY_FAILED);

        if (quoteAuthData->qeReportBody.isvsvn != g_QEISVSVN)
            OE_RAISE(OE_VERIFY_FAILED);

        // Ensure that the QE is not a debug supporting enclave.
        if (quoteAuthData->qeReportBody.attributes.flags & SGX_FLAGS_DEBUG)
            OE_RAISE(OE_VERIFY_FAILED);
    }
    result = OE_OK;

done:
    OE_ECPublicKeyFree(&leafPublicKey);
    OE_ECPublicKeyFree(&rootPublicKey);
    OE_ECPublicKeyFree(&expectedRootPublicKey);
    OE_ECPublicKeyFree(&attestationKey);
    OE_CertFree(&leafCert);
    OE_CertFree(&rootCert);
    OE_CertChainFree(&pckCertChain);

    return result;
}

#else

OE_Result VerifyQuoteImpl(
    const uint8_t* encQuote,
    uint32_t quoteSize,
    const uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    const uint8_t* encTcbInfoJson,
    uint32_t encTcbInfoJsonSize)
{
    OE_UNUSED(encQuote);
    OE_UNUSED(quoteSize);
    OE_UNUSED(encPemPckCertificate);
    OE_UNUSED(pemPckCertificateSize);
    OE_UNUSED(encPckCrl);
    OE_UNUSED(encPckCrlSize);
    OE_UNUSED(encTcbInfoJson);
    OE_UNUSED(encTcbInfoJsonSize);

    return OE_UNIMPLEMENTED;
}

#endif
