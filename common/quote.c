// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "quote.h"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sha.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>

#ifdef OE_USE_LIBSGX

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
    uint8_t buf[1 + sizeof(*key)] = {0x04};
    OE_Memcpy(buf + 1, key, sizeof(*key));

    return OE_ECPublicKeyFromBytes(
        publicKey, OE_EC_TYPE_SECP256R1, buf, sizeof(buf));
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
    OE_Cert pckCert = {0};
    OE_SHA256Context sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    OE_ECPublicKey attestationKey = {0};
    uint8_t asn1Signature[256];
    uint64_t asn1SignatureSize = sizeof(asn1Signature);

    OE_CHECK(
        _ParseQuote(
            quote,
            quoteSize,
            &sgxQuote,
            &quoteAuthData,
            &qeAuthData,
            &qeCertData));

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
        // TODO: Raise failure.
    }

    // TODO: If encPckCrl or encTcbInfoJson is not provided,
    // fetch it from provider via host.    
    

    // TODO: Enable this after Azure Quote Provider integration.
    // if (encPckCrl == 0 || encTcbInfoJson == 0)
    //     OE_RAISE(OE_FAILURE);

    // 1. If PckCertificate is provided. Parse and Validate it.
    // This must do:
    //      a. Assert subject == PCK_SUBJECT            (TODO)
    //      b. Assert !expired                          (TODO)
    //      c. Assert PCK_REQUIRED_EXTENSIONS exist.    (TODO)
    //      d. Assert PCK_REQUIRED_SGX_EXTENSIONS exist. (TODO)
    //      e. Assert !revoked                           (TODO)
    //      f. Assert that latestElements are not out of date using tcbInfo
    //      (TODO)
    //      g. Assert !revoked using tcbInfo (TODO)
    if (pemPckCertificate != NULL)
    {
        OE_CHECK(
            OE_CertReadPEM(pemPckCertificate, pemPckCertificateSize, &pckCert));
    }

    // 2. If pckCrl is provided. Parse and Validate it.
    // This must do:
    //      a. Assert !expired                  (TODO)
    //      b. Assert issuer == PCK_PROCESSOR_CRL_ISSUER or
    //      PCK_PLATFORM_CRL_ISSUER  (TODO)
    //      c. Assert issuer == pckCertificate.issuer (TODO)

    // 3. Quote validations
    // This must do:
    //      a. Assert version == OE_SGX_QUOTE_VERSION  (done)
    //      b. Assert qeCertData.type is a SGX_SUPPORTED_PCK_IDS (done)
    //      c. Verify qeCertData
    //          i.  Check parsedDataSize == data.size()   (N/A done during
    //          parsing)
    //      d. Verify SHA256 ECDSA (qeReportBodySignature, qeReportBody,
    //      PckCertificate.pubKey) (TODO)
    //      e. Assert SHA256 (attestationKey + qeAuthData.data) ==
    //      qeReportBody.reportData[0..32] (done)
    //      f. Verify SHA256 ECDSA (attestationKey, SGX_QUOTE_SIGNED_DATA,
    //      signature) (done)
    {
        if (sgxQuote->version != OE_SGX_QUOTE_VERSION)
        {
            OE_RAISE(OE_VERIFY_FAILED);
        }

        // TODO: Reenable this once Azure quote provider is integrated.
        //if (qeCertData.type != OE_SGX_PCK_ID_PCK_CERT_CHAIN)
        //    OE_RAISE(OE_UNSUPPORTED_QE_CERTIFICATION);

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

        OE_CHECK(
            _ReadPublicKey(&quoteAuthData->attestationKey, &attestationKey));

        OE_CHECK(OE_SHA256Init(&sha256Ctx));
        OE_CHECK(
            OE_SHA256Update(&sha256Ctx, sgxQuote, SGX_QUOTE_SIGNED_DATA_SIZE));
        OE_CHECK(OE_SHA256Final(&sha256Ctx, &sha256));

        OE_CHECK(
            OE_ECSignatureWriteASN1(
                asn1Signature,
                &asn1SignatureSize,
                quoteAuthData->signature.r,
                sizeof(quoteAuthData->signature.r),
                quoteAuthData->signature.s,
                sizeof(quoteAuthData->signature.s)));

        OE_CHECK(
            OE_ECPublicKeyVerify(
                &attestationKey,
                OE_HASH_TYPE_SHA256,
                (uint8_t*)&sha256,
                sizeof(sha256),
                asn1Signature,
                asn1SignatureSize));
    }

    result = OE_OK;

done:

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
