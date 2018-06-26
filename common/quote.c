// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "quote.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>

#include <string.h>

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

typedef struct _extension_info_t
{
    const char* name;
    const char* oid;
    uint8_t dataTag;
    uint32_t length;
} extension_info_t;

#define SGX_EXTENSION_OID_STR "1.2.840.113741.1.13.1"

#define SGX_EXTENSION_OID "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01"

static const extension_info_t g_OtherSgxExtensionInfos[2] = {
    {"DYNAMIC_PLATFORM", SGX_EXTENSION_OID "\x06"},
    {"CACHED_KEYS", SGX_EXTENSION_OID "\x07"}};

typedef void (*CallbackType)(
    uint8_t* oid,
    uint32_t oidLength,
    uint8_t dataTag,
    uint8_t* data,
    uint32_t dataSize,
    void* callbackData);

uint32_t _getASN1Length(uint8_t** ps)
{
    uint8_t* p = *ps;
    uint32_t length = *p++;
    uint8_t bytes = 0;

    if (length == 0x80)
    {
        length = 0;
        while (p[0] != 0 && p[1] != 0)
        {
            ++length;
            ++p;
        }
    }
    else if (length > 0x80)
    {
        bytes = (uint8_t)length - 0x80;
        length = 0;
        while (bytes > 0)
        {
            length = (length << 8) | *p;
            --bytes;
            ++p;
        }
    }
    *ps = p;
    return length;
}

#define ASN1_SEQUENCE_TAG (0x30)
#define ASN1_OCTET_STRING_TAG (0x04)
#define ASN1_INTEGER_TAG (0x02)
#define ASN1_OBJECT_ID_TAG (0x06)
#define ASN1_ENUMERATION_TAG (0x0a)

static void _ParseExtensions(
    uint8_t* p,
    uint8_t* end,
    CallbackType callback,
    void* callbackData)
{
    uint64_t length = 0;
    uint8_t* oid = NULL;
    uint64_t oidLength = 0;
    uint8_t* data = NULL;
    uint32_t dataLength = 0;
    uint8_t tag = 0;
    uint8_t* next = 0;
    uint8_t treatAsOidData = 0;
    uint8_t* start = 0;

    while (p < end)
    {
        tag = *p++;
        length = _getASN1Length(&p);
        start = p;
        next = p + length;

        if (length == 0x80)
            next += 2; // skip two zeros

        if (treatAsOidData)
        {
            // this next tag following the oid is the data.
            data = start;
            dataLength = length;
            callback(oid, oidLength, tag, data, dataLength, callbackData);
            treatAsOidData = 0;
        }
        else
        {
            if (tag == ASN1_SEQUENCE_TAG ||
                tag == ASN1_OCTET_STRING_TAG) // SEQUENCE OR OCTET_STRING
            {
                // nested sequence
                _ParseExtensions(p, p + length, callback, callbackData);
            }
            else if (tag == ASN1_OBJECT_ID_TAG) // OBJECT_ID
            {
                oid = p;
                oidLength = length;
                treatAsOidData = 1;
            }
        }

        p = next;
    }
}

static oe_result_t _GetSGXExtension(
    oe_cert_t* cert,
    uint8_t* data,
    uint32_t* dataSize)
{
    oe_result_t result = OE_FAILURE;
    uint64_t count = 0;
    uint64_t size = 0;
    OE_OIDString oid = {0};
    uint32_t sgxOIDLength = strlen(SGX_EXTENSION_OID_STR);

    OE_CHECK(oe_cert_extension_count(cert, &count));
    for (int i = 0; i < count; ++i)
    {
        size = *dataSize;
        OE_CHECK(oe_cert_get_extension(cert, i, &oid, data, &size));
        if (memcmp(oid.buf, SGX_EXTENSION_OID_STR, sgxOIDLength) == 0)
        {
            *dataSize = (uint32_t)size;
            result = OE_OK;
            break;
        }
    }
done:
    return result;
}

static int8_t _OIDEqual(uint8_t* oid, uint32_t oidLength, const char* expected)
{
    uint32_t expectedLength = strlen(expected);
    return (oidLength == expectedLength) &&
           (memcmp(oid, expected, oidLength) == 0);
}

typedef struct _ParsedExtensionInfo
{
    uint8_t* ppid;
    uint32_t ppidLength;
    uint8_t* tcb;
    uint32_t tcbSize;
    uint8_t* tcbCompSvn[17];
    uint32_t tcbCompSvnSize[17];
    uint8_t* pceSvn;
    uint32_t pceSvnSize;
    uint8_t* cpuSvn;
    uint32_t cpuSvnSize;
    uint8_t* pceId;
    uint32_t pceIdSize;
    uint8_t* fmspc;
    uint32_t fmspcSize;
    uint8_t* sgxType;
    uint32_t sgxTypeSize;
    uint16_t success;
    uint16_t errors;
} ParsedExtensionInfo;

static void callback(
    uint8_t* oid,
    uint32_t oidLength,
    uint8_t dataTag,
    uint8_t* data,
    uint32_t dataSize,
    ParsedExtensionInfo* parsedInfo)
{
    uint8_t tcbCompIdx = 0;
    const char* PPID_OID = SGX_EXTENSION_OID "\x01";
    const char* TCB_OID = SGX_EXTENSION_OID "\x02";
    const char* PCEID_OID = SGX_EXTENSION_OID "\x03";
    const char* FMSPC_OID = SGX_EXTENSION_OID "\x04";
    const char* SGX_TYPE_OID = SGX_EXTENSION_OID "\x05";

    const char* PCESVN_OID = SGX_EXTENSION_OID "\x02\x11";
    const char* CPUSVN_OID = SGX_EXTENSION_OID "\x02\x12";

    if (_OIDEqual(oid, oidLength, PPID_OID) && parsedInfo->ppid == NULL)
    {
        if (dataTag == ASN1_OCTET_STRING_TAG && dataSize == 16)
        {
            // printf("PPID_OID %x %d\n", *data, dataSize);
            parsedInfo->ppid = data;
            parsedInfo->ppidLength = dataSize;
            ++parsedInfo->success;
        }
    }
    else if (_OIDEqual(oid, oidLength, TCB_OID) && parsedInfo->tcb == NULL)
    {
        if (dataTag == ASN1_SEQUENCE_TAG)
        {
            // printf("TCB_OID %x %d\n", *data, dataSize);
            parsedInfo->tcb = data;
            parsedInfo->tcbSize = dataSize;
            ++parsedInfo->success;
            _ParseExtensions(
                data, data + dataSize, (CallbackType)callback, parsedInfo);
        }
    }
    else if (_OIDEqual(oid, oidLength, PCEID_OID) && parsedInfo->pceId == NULL)
    {
        if (dataTag == ASN1_OCTET_STRING_TAG && dataSize == 2)
        {
            // printf("PCEID_OID %x %d\n", *data, dataSize);
            parsedInfo->pceId = data;
            parsedInfo->pceIdSize = dataSize;
            ++parsedInfo->success;
        }
    }
    else if (_OIDEqual(oid, oidLength, FMSPC_OID) && parsedInfo->fmspc == NULL)
    {
        if (dataTag == ASN1_OCTET_STRING_TAG && dataSize == 6)
        {
            // printf("FMSPC_OID %x %d\n", *data, dataSize);
            parsedInfo->fmspc = data;
            parsedInfo->fmspcSize = dataSize;
            ++parsedInfo->success;
        }
    }
    else if (
        _OIDEqual(oid, oidLength, SGX_TYPE_OID) && parsedInfo->sgxType == NULL)
    {
        if (dataTag == ASN1_ENUMERATION_TAG && dataSize == 1)
        {
            // printf("SGX_TYPE_OID %x %d\n", *data, dataSize);
            parsedInfo->sgxType = data;
            parsedInfo->sgxTypeSize = dataSize;
            ++parsedInfo->success;
        }
    }
    else if (
        _OIDEqual(oid, oidLength, PCESVN_OID) && parsedInfo->pceSvn == NULL)
    {
        if (dataTag == ASN1_INTEGER_TAG && dataSize == 1)
        {
            // printf("PCESVN_OID %x %d\n", *data, dataSize);
            parsedInfo->pceSvn = data;
            parsedInfo->pceSvnSize = dataSize;
            ++parsedInfo->success;
        }
    }
    else if (
        _OIDEqual(oid, oidLength, CPUSVN_OID) && parsedInfo->cpuSvn == NULL)
    {
        if (dataTag == ASN1_OCTET_STRING_TAG && dataSize == 16)
        {
            // printf("CPUSVN_OID %x %d\n", *data, dataSize);
            parsedInfo->cpuSvn = data;
            parsedInfo->cpuSvnSize = dataSize;
            ++parsedInfo->success;
        }
    }
    else if (_OIDEqual(oid, oidLength - 1, TCB_OID))
    {
        // nested TCB extensions.
        tcbCompIdx = oid[oidLength - 1];
        if (tcbCompIdx < sizeof(parsedInfo->tcbCompSvn) /
                             sizeof(parsedInfo->tcbCompSvn[0]) &&
            parsedInfo->tcbCompSvn[tcbCompIdx] == NULL)
        {
            if (dataTag == ASN1_INTEGER_TAG)
            {
                // printf ("TCB_COMP_SVN_%d %x %d\n", tcbCompIdx, *data,
                // dataSize);
                parsedInfo->tcbCompSvn[tcbCompIdx] = data;
                parsedInfo->tcbCompSvnSize[tcbCompIdx] = dataSize;
                ++parsedInfo->success;
            }
        }
    }
}

static oe_result_t _ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* data,
    uint32_t dataSize,
    ParsedExtensionInfo* parsedInfo)
{
    oe_result_t result = OE_OK;

    OE_CHECK(_GetSGXExtension(cert, data, &dataSize));
    _ParseExtensions(data, data + dataSize, (CallbackType)callback, parsedInfo);

    // There are 23 expected extension objects.
    if (parsedInfo->success == 23)
        result = OE_OK;

done:
    return result;
}

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
    static ParsedExtensionInfo parsedInfo = {0};

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
            oe_cert_chain_read_pem(
                pemPckCertificate, pemPckCertificateSize, &pckCertChain));

        // Fetch leaf and root certificates.
        OE_CHECK(oe_cert_chain_get_leaf_cert(&pckCertChain, &leafCert));
        OE_CHECK(oe_cert_chain_get_root_cert(&pckCertChain, &rootCert));

        OE_CHECK(oe_cert_get_ec_public_key(&leafCert, &leafPublicKey));
        OE_CHECK(oe_cert_get_ec_public_key(&rootCert, &rootPublicKey));

        // Ensure that the root certificate matches root of trust.
        OE_CHECK(
            oe_ec_public_key_read_pem(
                (const uint8_t*)g_ExpectedRootCertificateKey,
                oe_strlen(g_ExpectedRootCertificateKey) + 1,
                &expectedRootPublicKey));

        OE_CHECK(
            oe_ec_public_key_equal(
                &rootPublicKey, &expectedRootPublicKey, &keyEqual));
        if (!keyEqual)
            OE_RAISE(OE_VERIFY_FAILED);

        OE_CHECK(_ParseSGXExtensions(&leafCert, data, dataSize, &parsedInfo));
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
        // Assert that the qe report's mr signer matches Intel's quoting
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
