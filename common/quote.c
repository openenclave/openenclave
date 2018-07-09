// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "quote.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>
#include "tcbinfo.h"

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

static oe_result_t _ParseQuote(
    const uint8_t* quote,
    uint32_t quoteSize,
    sgx_quote_t** sgxQuote,
    sgx_quote_auth_data_t** quoteAuthData,
    sgx_qe_auth_data_t* qeAuthData,
    sgx_qe_cert_data_t* qeCertData)
{
    oe_result_t result = OE_UNEXPECTED;

    const uint8_t* p = quote;
    const uint8_t* const quoteEnd = quote + quoteSize;

    if (quoteEnd < p)
    {
        // Pointer wrapped around.
        OE_RAISE(OE_QUOTE_PARSE_ERROR);
    }

    *sgxQuote = NULL;

    *sgxQuote = (sgx_quote_t*)p;
    p += sizeof(sgx_quote_t);
    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    if (p + (*sgxQuote)->signature_len != quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    *quoteAuthData = (sgx_quote_auth_data_t*)(*sgxQuote)->signature;
    p += sizeof(sgx_quote_auth_data_t);

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

static oe_result_t _ReadPublicKey(
    sgx_ecdsa256_key_t* key,
    oe_ec_public_key_t* publicKey)
{
    return oe_ec_public_key_from_coordinates(
        publicKey,
        OE_EC_TYPE_SECP256R1,
        key->x,
        sizeof(key->x),
        key->y,
        sizeof(key->y));
}

static oe_result_t _ECDSAVerify(
    oe_ec_public_key_t* publicKey,
    void* data,
    uint32_t dataSize,
    sgx_ecdsa256_signature_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_t sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t asn1Signature[256];
    uint64_t asn1SignatureSize = sizeof(asn1Signature);

    OE_CHECK(oe_sha256_init(&sha256Ctx));
    OE_CHECK(oe_sha256_update(&sha256Ctx, data, dataSize));
    OE_CHECK(oe_sha256_final(&sha256Ctx, &sha256));

    OE_CHECK(
        oe_ecdsa_signature_write_der(
            asn1Signature,
            &asn1SignatureSize,
            signature->r,
            sizeof(signature->r),
            signature->s,
            sizeof(signature->s)));

    OE_CHECK(
        oe_ec_public_key_verify(
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

static oe_result_t _GetRevocationInfo(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    uint32_t hostArgsBufferSize = sizeof(*args);
    uint8_t* hostArgsBuffer = NULL;
    oe_get_revocation_info_args_t* hostArgs = NULL;
    uint8_t* p = 0;
    uint32_t crlUrlSizes[2] = {0};

    if (args == NULL || args->numCrlUrls != 2 || args->crlUrls[0] == NULL ||
        args->crlUrls[1] == NULL)
        OE_RAISE(OE_FAILURE);

    if (args->numCrlUrls != 2)
        OE_RAISE(OE_FAILURE);

    for (uint32_t i = 0; i < args->numCrlUrls; ++i)
    {
        crlUrlSizes[i] = oe_strlen(args->crlUrls[i]) + 1;
        hostArgsBufferSize += crlUrlSizes[i];
    }

    hostArgsBuffer = oe_host_malloc(hostArgsBufferSize);
    if (hostArgsBuffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy args struct.
    p = hostArgsBuffer;
    hostArgs = (oe_get_revocation_info_args_t*)p;
    *hostArgs = *args;
    p += sizeof(*hostArgs);

    // Copy input buffers.
    for (uint32_t i = 0; i < args->numCrlUrls; ++i)
    {
        hostArgs->crlUrls[i] = (const char*)p;
        oe_memcpy(p, args->crlUrls[i], crlUrlSizes[i]);
        p += crlUrlSizes[i];
    }

    OE_CHECK(
        oe_ocall(
            OE_FUNC_GET_REVOCATION_INFO,
            (uint64_t)hostArgs,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));
    *args = *hostArgs;
    if (args->result != OE_OK)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;
done:
    if (hostArgsBuffer)
        oe_host_free(hostArgsBuffer);

    // if (args && args->hostOutBuffer)
    //     oe_host_free(args->hostOutBuffer);

    return result;
}

oe_result_t VerifyQuoteImpl(
    const uint8_t* quote,
    uint32_t quoteSize,
    const uint8_t* pemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* pckCrl,
    uint32_t pckCrlSize,
    const uint8_t* tcbInfoJson,
    uint32_t tcbInfoJsonSize)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_quote_t* sgxQuote = NULL;
    sgx_quote_auth_data_t* quoteAuthData = NULL;
    sgx_qe_auth_data_t qeAuthData = {0};
    sgx_qe_cert_data_t qeCertData = {0};
    oe_cert_chain_t pckCertChain = {0};
    oe_sha256_context_t sha256Ctx = {0};
    OE_SHA256 sha256 = {0};
    oe_ec_public_key_t attestationKey = {0};
    oe_cert_t leafCert = {0};
    oe_cert_t rootCert = {0};
    oe_ec_public_key_t leafPublicKey = {0};
    oe_ec_public_key_t rootPublicKey = {0};
    oe_ec_public_key_t expectedRootPublicKey = {0};
    bool keyEqual = false;
    static uint8_t data[16 * 1024];
    uint32_t dataSize = sizeof(data);
    ParsedExtensionInfo parsedInfo = {0};
    oe_get_revocation_info_args_t revocationArgs = {0};

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
            oe_cert_chain_read_pem(&pckCertChain,
                pemPckCertificate, pemPckCertificateSize));

        // Fetch leaf and root certificates.
        OE_CHECK(oe_cert_chain_get_leaf_cert(&pckCertChain, &leafCert));
        OE_CHECK(oe_cert_chain_get_root_cert(&pckCertChain, &rootCert));

        OE_CHECK(oe_cert_get_ec_public_key(&leafCert, &leafPublicKey));
        OE_CHECK(oe_cert_get_ec_public_key(&rootCert, &rootPublicKey));

        // Ensure that the root certificate matches root of trust.
        OE_CHECK(
            oe_ec_public_key_read_pem(
                &expectedRootPublicKey,
                (const uint8_t*)g_ExpectedRootCertificateKey,
                oe_strlen(g_ExpectedRootCertificateKey) + 1
                ));

        OE_CHECK(
            oe_ec_public_key_equal(
                &rootPublicKey, &expectedRootPublicKey, &keyEqual));
        if (!keyEqual)
            OE_RAISE(OE_VERIFY_FAILED);

        OE_CHECK(ParseSGXExtensions(&leafCert, data, &dataSize, &parsedInfo));

        oe_memcpy(
            revocationArgs.fmspc, parsedInfo.fmspc, sizeof(parsedInfo.fmspc));
        revocationArgs.crlUrls[0] = "https://"
                                    "certificates.trustedservices.intel.com/"
                                    "IntelSGXPCKProcessor.crl";
        revocationArgs.crlUrls[1] = "https://"
                                    "certificates.trustedservices.intel.com/"
                                    "IntelSGXPCKProcessor.crl";
        revocationArgs.numCrlUrls = 2;
        OE_CHECK(_GetRevocationInfo(&revocationArgs));

        OE_CHECK(
            oe_enforce_tcb_info(
                revocationArgs.tcbInfo,
                revocationArgs.tcbInfoSize,
                &parsedInfo,
                true /* require components to be uptodate. */));
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
        OE_CHECK(oe_sha256_init(&sha256Ctx));
        OE_CHECK(
            oe_sha256_update(
                &sha256Ctx,
                (const uint8_t*)&quoteAuthData->attestationKey,
                sizeof(quoteAuthData->attestationKey)));
        if (qeAuthData.size > 0)
        {
            OE_CHECK(
                oe_sha256_update(&sha256Ctx, qeAuthData.data, qeAuthData.size));
        }
        OE_CHECK(oe_sha256_final(&sha256Ctx, &sha256));

        if (!oe_constant_time_mem_equal(
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
        // Assert that the qe report's MRSIGNER matches Intel's quoting
        // enclave's mrsigner.
        if (!oe_constant_time_mem_equal(
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
    oe_ec_public_key_free(&leafPublicKey);
    oe_ec_public_key_free(&rootPublicKey);
    oe_ec_public_key_free(&expectedRootPublicKey);
    oe_ec_public_key_free(&attestationKey);
    oe_cert_free(&leafCert);
    oe_cert_free(&rootCert);
    oe_cert_chain_free(&pckCertChain);

    return result;
}

#else

oe_result_t VerifyQuoteImpl(
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
