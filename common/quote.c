// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
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

#ifdef OE_BUILD_ENCLAVE

OE_Result OE_GetRevocationInfo(OE_GetRevocationInfoArgs* revocationInfo)
{
    OE_HostPrintf("Fetching revocation info from provider via host\n");
    return OE_OCall(
        OE_FUNC_GET_REVOCATION_INFO,
        (uint64_t)revocationInfo,
        NULL,
        OE_OCALL_FLAG_NOT_REENTRANT);
}

#endif

#ifdef OE_USE_LIBSGX

OE_INLINE uint16_t readUint16(const uint8_t* p)
{
    return (p[0] << 0) | (p[1] << 8);
}

OE_INLINE uint16_t readUint32(const uint8_t* p)
{
    return (p[0] << 0) | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static const SGX_PCKId SGX_SUPPORTED_PCK_IDS[5] = {
    SGX_PCK_ID_PLAIN_PPID,
    SGX_PCK_ID_ENCRYPTED_PPID_2048,
    SGX_PCK_ID_ENCRYPTED_PPID_3072,
    SGX_PCK_ID_PCK_CERTIFICATE,
    SGX_PCK_ID_PCK_CERT_CHAIN};

static OE_Result _ParseQuote(
    const uint8_t* encQuote,
    uint32_t quoteSize,
    SGX_Quote** sgxQuote,
    SGX_QuoteAuthData** quoteAuthData,
    SGX_QEAuthData* qeAuthData,
    SGX_QECertData* qeCertData)
{
    OE_Result result = OE_UNEXPECTED;

    const uint8_t* p = encQuote;
    const uint8_t* const quoteEnd = encQuote + quoteSize;

    *sgxQuote = NULL;

    *sgxQuote = (SGX_Quote*)p;
    p += sizeof(SGX_Quote);
    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    if (p + (*sgxQuote)->signature_len != quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    *quoteAuthData = (SGX_QuoteAuthData*)(*sgxQuote)->signature;
    p += sizeof(SGX_QuoteAuthData);

    qeAuthData->size = readUint16(p);
    p += 2;
    qeAuthData->data = (uint8_t*)p;
    p += qeAuthData->size;

    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    qeCertData->type = readUint16(p);
    p += 2;
    qeCertData->size = readUint32(p);
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
    const uint8_t* encQuote,
    uint32_t quoteSize,
    const uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    const uint8_t* encTcbInfoJson,
    uint32_t encTcbInfoJsonSize)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_Quote* sgxQuote = NULL;
    SGX_QuoteAuthData* quoteAuthData = NULL;
    SGX_QEAuthData qeAuthData = {0};
    SGX_QECertData qeCertData = {0};
    OE_Cert pckCert = {0};
    OE_SHA256Context sha256Ctx = {};
    OE_SHA256 sha256 = {0};
    OE_ECPublicKey attestationKey = {0};
    uint8_t asn1Signature[256];
    uint64_t asn1SignatureSize = sizeof(asn1Signature);
    OE_GetRevocationInfoArgs revocationInfo = {0};

    uint8_t found = 0;
    uint16_t i;

    OE_CHECK(
        _ParseQuote(
            encQuote,
            quoteSize,
            &sgxQuote,
            &quoteAuthData,
            &qeAuthData,
            &qeCertData));

    // The certificate provided in the quote is preferred.
    if (qeCertData.type == SGX_PCK_ID_PCK_CERT_CHAIN)
    {
        if (qeCertData.size == 0)
            OE_RAISE(OE_FAILURE);
        encPemPckCertificate = qeCertData.data;
        pemPckCertificateSize = qeCertData.size;
    }

    // If encPckCrl or encTcbInfoJson is not provided,
    // fetch it from provider via host.
    // Disabled for now.
    if (false && (encPckCrl == 0 || encTcbInfoJson == 0))
    {
        OE_CHECK(OE_GetRevocationInfo(&revocationInfo));

        // TODO: Copy buffers to enclave memory.
        encPckCrl = revocationInfo.crl;
        encPckCrlSize = revocationInfo.crlSize;

        encTcbInfoJson = revocationInfo.tcbInfo;
        encTcbInfoJsonSize = revocationInfo.tcbInfoSize;
    }

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
    if (encPemPckCertificate != NULL)
    {
        OE_CHECK(
            OE_CertReadPEM(
                encPemPckCertificate, pemPckCertificateSize, &pckCert));
    }

    // 2. If pckCrl is provided. Parse and Validate it.
    // This must do:
    //      a. Assert !expired                  (TODO)
    //      b. Assert issuer == PCK_PROCESSOR_CRL_ISSUER or
    //      PCK_PLATFORM_CRL_ISSUER  (TODO)
    //      c. Assert issuer == pckCertificate.issuer (TODO)

    // 3. Quote validations
    // This must do:
    //      a. Assert version == SGX_QUOTE_VERSION  (done)
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
        if (sgxQuote->version != SGX_QUOTE_VERSION)
        {
            OE_RAISE(OE_VERIFY_FAILED);
        }

        found = 0;
        for (i = 0; i < sizeof(SGX_SUPPORTED_PCK_IDS) /
                            sizeof(SGX_SUPPORTED_PCK_IDS[0]);
             ++i)
        {
            if (qeCertData.type == SGX_SUPPORTED_PCK_IDS[i])
            {
                found = 1;
                break;
            }
        }

        if (!found)
            OE_RAISE(OE_UNSUPPORTED_QE_CERTIFICATION);

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

        // OE_CHECK(
        //     OE_ECDSA256_SHA_Verify(
        //         (const OE_ECDSA256Key*)&quoteAuthData->attestationKey,
        //         sgxQuote,
        //         SGX_QUOTE_SIGNED_DATA_SIZE,
        //         (const OE_ECDSA256Signature*)&quoteAuthData->signature));
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
    if (revocationInfo.memoryAllocatedInHost)
    {
        OE_HostFree(revocationInfo.memoryAllocatedInHost);
    }

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
