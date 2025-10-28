// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "quote.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/tdx/tdxquote.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/crypto/ec.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "collateral.h"
#include "endorsements.h"
#include "qeidentity.h"

#include <time.h>

#ifdef OE_BUILD_ENCLAVE
#include "../../enclave/sgx/verifier.h"
#include "platform_t.h"
#else
#include "../../host/sgx/quote.h"
#endif

#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY // allow overrode by oeutil
// Defined by tools/oeutil/host/generate_evidence.cpp
extern const char* _trusted_root_key_pem;
#else // use hard-coded value
// Public key of Intel's root certificate.
static const char* _trusted_root_key_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
    "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
    "-----END PUBLIC KEY-----\n";
#endif

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
// Defined in tools/oeutil/host/generate_evidence.cpp
extern bool _should_skip_date_check;
#endif

// Max length of SGX DCAP QVL/QvE returned supplemental data
#define MAX_SUPPLEMENTAL_DATA_SIZE 1000

OE_INLINE uint16_t ReadUint16(const uint8_t* p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

OE_INLINE uint32_t ReadUint32(const uint8_t* p)
{
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static oe_result_t _validate_sgx_quote(const sgx_quote_t* sgx_quote)
{
    oe_result_t result = OE_OK;

    if (sgx_quote->version != OE_SGX_QUOTE_VERSION)
    {
        OE_RAISE_MSG(
            OE_QUOTE_VERIFICATION_ERROR,
            "Unexpected quote version sgx_quote->version=%d",
            sgx_quote->version);
    }

done:
    return result;
}

static oe_result_t _validate_qe_cert_data(
    const sgx_qe_cert_data_t* qe_cert_data)
{
    oe_result_t result = OE_OK;

    // The certificate provided in the quote is preferred.
    if (qe_cert_data->type != OE_SGX_PCK_ID_PCK_CERT_CHAIN)
        OE_RAISE_MSG(
            OE_MISSING_CERTIFICATE_CHAIN,
            "Unexpected certificate type (qe_cert_data->type=%d)",
            qe_cert_data->type);

    if (qe_cert_data->size == 0)
        OE_RAISE_MSG(
            OE_QUOTE_VERIFICATION_ERROR,
            "Quoting enclave certificate data is empty.",
            NULL);

    if (qe_cert_data->data == NULL)
        OE_RAISE_MSG(
            OE_MISSING_CERTIFICATE_CHAIN,
            "No PCK certificate found in SGX quote.",
            NULL);
done:
    return result;
}

static oe_result_t _parse_quote(
    const uint8_t* quote,
    size_t quote_size,
    sgx_quote_t** sgx_quote,
    sgx_quote_auth_data_t** quote_auth_data,
    sgx_qe_auth_data_t* qe_auth_data,
    sgx_qe_cert_data_t* qe_cert_data)
{
    oe_result_t result = OE_UNEXPECTED;

    const uint8_t* p = quote;
    sgx_quote_t* _sgx_quote = (sgx_quote_t*)p;
    const uint8_t* const quote_end = quote + quote_size;

    if (quote_end < p)
        // Pointer wrapped around.
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parsing error.  Pointer wrapper around.",
            NULL);

    p += sizeof(sgx_quote_t);

    if (p > quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing SGX quote, before signature.",
            NULL);

    if (p + _sgx_quote->signature_len != quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing SGX signature.",
            NULL);

    if (quote_auth_data)
        *quote_auth_data = (sgx_quote_auth_data_t*)p;

    p += sizeof(sgx_quote_auth_data_t);

    qe_auth_data->size = ReadUint16(p);
    p += 2;
    qe_auth_data->data = (uint8_t*)p;
    p += qe_auth_data->size;

    if (p > quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing QE authorization data.",
            NULL);

    qe_cert_data->type = ReadUint16(p);
    p += 2;
    qe_cert_data->size = ReadUint32(p);
    p += 4;
    qe_cert_data->data = (uint8_t*)p;
    p += qe_cert_data->size;

    if (p != quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Unexpected quote length while parsing.",
            NULL);

    //
    // Validation
    //
    OE_CHECK_MSG(
        _validate_sgx_quote(_sgx_quote), "SGX quote validation failed.", NULL);

    OE_CHECK_MSG(
        _validate_qe_cert_data(qe_cert_data),
        "Failed to validate QE certificate data.",
        NULL);

    if (sgx_quote)
        *sgx_quote = _sgx_quote;

    result = OE_OK;
done:
    return result;
}

#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
// Parse TDX quote (v4 or v5) and extract certification data
static oe_result_t _parse_tdx_quote(
    const uint8_t* quote,
    size_t quote_size,
    tdx_quote_t** tdx_quote,
    tdx_quote_auth_data_t** quote_auth_data,
    sgx_qe_auth_data_t* qe_auth_data,
    sgx_qe_cert_data_t* qe_cert_data)
{
    oe_result_t result = OE_UNEXPECTED;

    const uint8_t* p = quote;
    tdx_quote_t* _tdx_quote = (tdx_quote_t*)p;
    const uint8_t* const quote_end = quote + quote_size;

    if (quote_end < p)
        // Pointer wrapped around.
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "TDX quote parsing error. Pointer wrapped around.",
            NULL);

    // Determine quote version and size of fixed header
    size_t quote_body_end;
    uint32_t signature_len;

    if (_tdx_quote->version == 4)
    {
        quote_body_end = sizeof(tdx_quote_t);
        signature_len = _tdx_quote->signature_len;
    }
    else if (_tdx_quote->version == 5)
    {
        // Version 5 has variable body size
        tdx_quote_v5_t* v5_quote = (tdx_quote_v5_t*)p;
        quote_body_end = sizeof(tdx_quote_v5_t) + v5_quote->size;
        // signature_len is right after the variable body
        const uint8_t* sig_len_ptr = (const uint8_t*)v5_quote + quote_body_end;
        signature_len = ReadUint32(sig_len_ptr);
        quote_body_end += 4; // Add signature_len field size
    }
    else
    {
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR, "Unsupported TDX quote version.", NULL);
    }

    p += quote_body_end;

    if (p > quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing TDX quote header.",
            NULL);

    if (p + signature_len != quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error: TDX signature length mismatch.",
            NULL);

    // Parse authentication data
    // tdx_quote_auth_data_t has signature and attestation_key (128 bytes total)
    // The certification_data[] is a flexible array member at the end
    if (quote_auth_data)
        *quote_auth_data = (tdx_quote_auth_data_t*)p;

    // Move past signature (64) and attestation_key (64) = 128 bytes total
    p += sizeof(tdx_quote_auth_data_t);

    // Now p points to certification_data[] which contains
    // tdx_qe_report_certification_data_t:
    //   - tdx_qe_certification_data_t: 6 bytes
    //   - qe_report_body (sgx_report_body_t, 384 bytes)
    //   - signature (sgx_ecdsa256_signature_t, 64 bytes)
    //   - auth_certification_data[] (variable):
    //       - qe_auth_data_size (2 bytes)
    //       - qe_auth_data (variable)
    //       - qe_cert_data_type (2 bytes)
    //       - qe_cert_data_size (4 bytes)
    //       - qe_cert_data (variable)

    if (p + sizeof(tdx_qe_certification_data_t) > quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "TDX quote data size too small to contain certification data.",
            NULL);

    tdx_qe_certification_data_t* cert_data = (tdx_qe_certification_data_t*)p;
    cert_data->type = ReadUint16(p);
    p += 2;
    cert_data->size = ReadUint32(p);
    p += 4;

    // Validation: Check cert data type (should be 6 for QE report)
    if (cert_data->type != TDX_QE_CERTIFICATION_DATA_TYPE_QE_REPORT)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Invalid TDX QE certification data type.",
            NULL);

    if (p + cert_data->size != quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "TDX QE certification data size mismatch.",
            NULL);

    // Now parse the QE report body and signature
    // Note: We can't use tdx_qe_report_certification_data_t directly because
    // of the 6-byte prefix
    p += sizeof(sgx_report_body_t);        // 384 bytes
    p += sizeof(sgx_ecdsa256_signature_t); // 64 bytes
    // Now at offset: 706 + 128 + 6 + 384 + 64 = 1288

    // Parse qe_auth_data
    qe_auth_data->size = ReadUint16(p);
    p += 2;
    qe_auth_data->data = (uint8_t*)p;
    p += qe_auth_data->size;

    if (p > quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing TDX QE authorization data.",
            NULL);

    // Parse QE cert data (certificate chain)
    qe_cert_data->type = ReadUint16(p);
    p += 2;
    qe_cert_data->size = ReadUint32(p);
    p += 4;
    qe_cert_data->data = (uint8_t*)p;
    p += qe_cert_data->size;

    if (p != quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Unexpected TDX quote length while parsing.",
            NULL);

    // Validation: Check cert data type (should be 5 for PCK cert chain)
    if (qe_cert_data->type != TDX_QE_CERTIFICATION_DATA_TYPE_PCK_CERT_CHAIN)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Invalid TDX QE certificate data type.",
            NULL);

    if (tdx_quote)
        *tdx_quote = _tdx_quote;

    result = OE_OK;
done:
    return result;
}
#endif // OEUTIL_TCB_ALLOW_ANY_ROOT_KEY

static oe_result_t _read_public_key(
    sgx_ecdsa256_key_t* key,
    oe_ec_public_key_t* public_key)
{
    return oe_ec_public_key_from_coordinates(
        public_key,
        OE_EC_TYPE_SECP256R1,
        key->x,
        sizeof(key->x),
        key->y,
        sizeof(key->y));
}

static oe_result_t _ecdsa_verify(
    oe_ec_public_key_t* public_key,
    void* data,
    size_t data_size,
    sgx_ecdsa256_signature_t* signature)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t asn1_signature[256];
    size_t asn1_signature_size = sizeof(asn1_signature);

    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, data, data_size));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    OE_CHECK(oe_ecdsa_signature_write_der(
        asn1_signature,
        &asn1_signature_size,
        signature->r,
        sizeof(signature->r),
        signature->s,
        sizeof(signature->s)));

    OE_CHECK(oe_ec_public_key_verify(
        public_key,
        OE_HASH_TYPE_SHA256,
        (uint8_t*)&sha256,
        sizeof(sha256),
        asn1_signature,
        asn1_signature_size));

    result = OE_OK;
done:
    return result;
}

// User should free *pem_data after use.
static oe_result_t _ec_public_key_write_pem(
    const oe_ec_public_key_t* public_key,
    uint8_t** pem_data,
    size_t* pem_size)
{
    // First call to get key_size
    oe_result_t result =
        oe_ec_public_key_write_pem(public_key, *pem_data, pem_size);

    if (result == OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (result != OE_BUFFER_TOO_SMALL)
        OE_RAISE(result);

    // Call again to get key
    *pem_data = (uint8_t*)oe_malloc(*pem_size);
    if (*pem_data == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_ec_public_key_write_pem(public_key, *pem_data, pem_size);

done:
    return result;
}

static oe_result_t oe_verify_quote_internal(
    const uint8_t* quote,
    size_t quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_quote_t* sgx_quote = NULL;
    sgx_quote_auth_data_t* quote_auth_data = NULL;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};
    oe_cert_chain_t pck_cert_chain = {0};
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256 = {0};
    oe_ec_public_key_t attestation_key = {0};
    oe_cert_t leaf_cert = {0};
    oe_cert_t root_cert = {0};
    oe_cert_t intermediate_cert = {0};
    oe_ec_public_key_t leaf_public_key = {0};
    oe_ec_public_key_t root_public_key = {0};
    oe_ec_public_key_t expected_root_public_key = {0};
    bool key_equal = false;

    uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;

    OE_CHECK_MSG(
        _parse_quote(
            quote,
            quote_size,
            &sgx_quote,
            &quote_auth_data,
            &qe_auth_data,
            &qe_cert_data),
        "Failed to parse quote. %s",
        oe_result_str(result));

    pem_pck_certificate = qe_cert_data.data;
    pem_pck_certificate_size = qe_cert_data.size;

    // PckCertificate Chain validations.
    {
        // Read and validate the chain.
        OE_CHECK_MSG(
            oe_cert_chain_read_pem(
                &pck_cert_chain, pem_pck_certificate, pem_pck_certificate_size),
            "Failed to parse certificate chain.",
            NULL);

        // Fetch leaf and root certificates.
        OE_CHECK_MSG(
            oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert),
            "Failed to get leaf certificate.",
            NULL);
        OE_CHECK_MSG(
            oe_cert_chain_get_root_cert(&pck_cert_chain, &root_cert),
            "Failed to get root certificate.",
            NULL);
        OE_CHECK_MSG(
            oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert),
            "Failed to get intermediate certificate.",
            NULL);

        // Get public keys.
        OE_CHECK_MSG(
            oe_cert_get_ec_public_key(&leaf_cert, &leaf_public_key),
            "Failed to get leaf cert public key.",
            NULL);
        OE_CHECK_MSG(
            oe_cert_get_ec_public_key(&root_cert, &root_public_key),
            "Failed to get root cert public key.",
            NULL);

        // Ensure that the root certificate matches root of trust.
        OE_CHECK_MSG(
            oe_ec_public_key_read_pem(
                &expected_root_public_key,
                (const uint8_t*)_trusted_root_key_pem,
                oe_strlen(_trusted_root_key_pem) + 1),
            "Failed to read expected root cert key.",
            NULL);
        OE_CHECK_MSG(
            oe_ec_public_key_equal(
                &root_public_key, &expected_root_public_key, &key_equal),
            "Failed to compare keys.",
            NULL);
        if (!key_equal)
        {
            // Convert public keys to PEM format for logging.
            uint8_t* key = NULL;
            size_t key_size = 0;

            oe_result_t ret =
                _ec_public_key_write_pem(&root_public_key, &key, &key_size);

            if (ret == OE_OK)
            {
                OE_TRACE_VERBOSE(
                    "Expected root public key:\n%s\nActual root public "
                    "key:\n%s\n",
                    _trusted_root_key_pem,
                    key);
            }
            else
            {
                OE_TRACE_ERROR(
                    "Failed to convert public key to PEM format. error=%s\n",
                    oe_result_str(ret));
            }

            oe_free(key);

            OE_RAISE_MSG(
                OE_QUOTE_VERIFICATION_ERROR,
                "Failed to verify root public key.",
                NULL);
        }
    }

    // Quote validations.
    {
        // Verify SHA256 ECDSA (qe_report_body_signature, qe_report_body,
        // PckCertificate.pub_key)
        //
        // Hash with PCK(QE report body) == QE report body signature
        //
        OE_CHECK_MSG(
            _ecdsa_verify(
                &leaf_public_key,
                &quote_auth_data->qe_report_body,
                sizeof(quote_auth_data->qe_report_body),
                &quote_auth_data->qe_report_body_signature),
            "QE report signature validation using PCK public key + SHA256 "
            "ECDSA",
            NULL);

        // Assert SHA256 (attestation_key + qe_auth_data.data) ==
        // qe_report_body.report_data[0..32]
        OE_CHECK(oe_sha256_init(&sha256_ctx));
        OE_CHECK(oe_sha256_update(
            &sha256_ctx,
            (const uint8_t*)&quote_auth_data->attestation_key,
            sizeof(quote_auth_data->attestation_key)));
        if (qe_auth_data.size > 0)
            OE_CHECK(oe_sha256_update(
                &sha256_ctx, qe_auth_data.data, qe_auth_data.size));
        OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

        if (!oe_constant_time_mem_equal(
                &sha256,
                &quote_auth_data->qe_report_body.report_data,
                sizeof(sha256)))
            OE_RAISE_MSG(
                OE_QUOTE_VERIFICATION_ERROR,
                "QE authentication data signature verification failed.",
                NULL);

        // Verify SHA256 ECDSA (attestation_key, SGX_QUOTE_SIGNED_DATA,
        // signature)
        //
        // Hash with attestation_key(sgx_quote) == quote_auth_data signature
        //
        OE_CHECK(_read_public_key(
            &quote_auth_data->attestation_key, &attestation_key));
        OE_CHECK_MSG(
            _ecdsa_verify(
                &attestation_key,
                sgx_quote,
                SGX_QUOTE_SIGNED_DATA_SIZE,
                &quote_auth_data->signature),
            "Report signature validation using attestation key + SHA256 ECDSA",
            NULL);
    }

    result = OE_OK;

done:
    oe_ec_public_key_free(&leaf_public_key);
    oe_ec_public_key_free(&root_public_key);
    oe_ec_public_key_free(&expected_root_public_key);
    oe_ec_public_key_free(&attestation_key);
    oe_cert_free(&leaf_cert);
    oe_cert_free(&root_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_chain_free(&pck_cert_chain);
    return result;
}

#ifdef OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
// Internal TDX quote verification using OE's certificate validation
// instead of Intel QVL library. This allows using pre-production root
// certificates.
oe_result_t oe_verify_tdx_quote_internal(
    const uint8_t* quote,
    size_t quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    tdx_quote_t* tdx_quote = NULL;
    tdx_quote_auth_data_t* quote_auth_data = NULL;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};
    oe_cert_chain_t pck_cert_chain = {0};
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256 = {0};
    oe_ec_public_key_t attestation_key = {0};
    oe_cert_t leaf_cert = {0};
    oe_cert_t root_cert = {0};
    oe_cert_t intermediate_cert = {0};
    oe_ec_public_key_t leaf_public_key = {0};
    oe_ec_public_key_t root_public_key = {0};
    oe_ec_public_key_t expected_root_public_key = {0};
    bool key_equal = false;

    uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;

    OE_TRACE_INFO("TDX quote internal verification (bypassing Intel QVL)");

    OE_CHECK_MSG(
        _parse_tdx_quote(
            quote,
            quote_size,
            &tdx_quote,
            &quote_auth_data,
            &qe_auth_data,
            &qe_cert_data),
        "Failed to parse TDX quote. %s",
        oe_result_str(result));

    pem_pck_certificate = qe_cert_data.data;
    pem_pck_certificate_size = qe_cert_data.size;

    // PCK Certificate Chain validations (same as SGX)
    {
        // Read and validate the chain.
        OE_CHECK_MSG(
            oe_cert_chain_read_pem(
                &pck_cert_chain, pem_pck_certificate, pem_pck_certificate_size),
            "Failed to parse TDX certificate chain.",
            NULL);

        // Fetch leaf and root certificates.
        OE_CHECK_MSG(
            oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert),
            "Failed to get TDX leaf certificate.",
            NULL);
        OE_CHECK_MSG(
            oe_cert_chain_get_root_cert(&pck_cert_chain, &root_cert),
            "Failed to get TDX root certificate.",
            NULL);
        OE_CHECK_MSG(
            oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert),
            "Failed to get TDX intermediate certificate.",
            NULL);

        // Get public keys.
        OE_CHECK_MSG(
            oe_cert_get_ec_public_key(&leaf_cert, &leaf_public_key),
            "Failed to get TDX leaf cert public key.",
            NULL);
        OE_CHECK_MSG(
            oe_cert_get_ec_public_key(&root_cert, &root_public_key),
            "Failed to get TDX root cert public key.",
            NULL);

        // Ensure that the root certificate matches root of trust.
        OE_CHECK_MSG(
            oe_ec_public_key_read_pem(
                &expected_root_public_key,
                (const uint8_t*)_trusted_root_key_pem,
                oe_strlen(_trusted_root_key_pem) + 1),
            "Failed to read expected TDX root cert key.",
            NULL);
        OE_CHECK_MSG(
            oe_ec_public_key_equal(
                &root_public_key, &expected_root_public_key, &key_equal),
            "Failed to compare TDX keys.",
            NULL);

        if (!key_equal)
        {
            // Convert public keys to PEM format for logging.
            uint8_t* key = NULL;
            size_t key_size = 0;

            oe_result_t ret =
                _ec_public_key_write_pem(&root_public_key, &key, &key_size);

            if (ret == OE_OK)
            {
                OE_TRACE_VERBOSE(
                    "Expected TDX root public key:\n%s\nActual TDX root public "
                    "key:\n%s\n",
                    _trusted_root_key_pem,
                    key);
            }
            else
            {
                OE_TRACE_ERROR(
                    "Failed to convert TDX public key to PEM format. "
                    "error=%s\n",
                    oe_result_str(ret));
            }

            oe_free(key);

            OE_RAISE_MSG(
                OE_QUOTE_VERIFICATION_ERROR,
                "Failed to verify TDX root public key.",
                NULL);
        }
    }

    // TDX Quote signature validations
    // We calculated pointers to QE report and signature during parsing
    // Reconstruct them here
    const uint8_t* cert_data_start =
        (const uint8_t*)quote_auth_data + sizeof(tdx_quote_auth_data_t);
    const uint8_t* qe_report_ptr =
        cert_data_start + sizeof(tdx_qe_certification_data_t);
    const uint8_t* qe_sig_ptr = qe_report_ptr + sizeof(sgx_report_body_t);

    sgx_report_body_t* qe_report_body = (sgx_report_body_t*)qe_report_ptr;
    sgx_ecdsa256_signature_t* qe_signature =
        (sgx_ecdsa256_signature_t*)qe_sig_ptr;

    {
        // Verify SHA256 ECDSA (qe_report_body_signature, qe_report_body,
        // PckCertificate.pub_key)
        OE_CHECK_MSG(
            _ecdsa_verify(
                &leaf_public_key,
                qe_report_body,
                sizeof(sgx_report_body_t),
                qe_signature),
            "TDX QE report signature validation using PCK public key + SHA256 "
            "ECDSA",
            NULL);

        // Assert SHA256 (attestation_key + qe_auth_data.data) ==
        // qe_report_body.report_data[0..32]
        OE_CHECK(oe_sha256_init(&sha256_ctx));
        OE_CHECK(oe_sha256_update(
            &sha256_ctx,
            (const uint8_t*)&quote_auth_data->attestation_key,
            sizeof(quote_auth_data->attestation_key)));
        if (qe_auth_data.size > 0)
            OE_CHECK(oe_sha256_update(
                &sha256_ctx, qe_auth_data.data, qe_auth_data.size));
        OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

        if (!oe_constant_time_mem_equal(
                &sha256, &qe_report_body->report_data, sizeof(sha256)))
            OE_RAISE_MSG(
                OE_QUOTE_VERIFICATION_ERROR,
                "TDX QE report data hash mismatch.",
                NULL);

        // Verify the TDX report signature (attestation_key signs the TDX report
        // body)
        OE_CHECK_MSG(
            _read_public_key(
                &quote_auth_data->attestation_key, &attestation_key),
            "Failed to read TDX attestation key.",
            NULL);

        // For TDX v4, the report body starts at offset 48
        // For TDX v5, it's at offset 54 + variable header
        void* report_body_ptr;
        size_t report_body_size;

        if (tdx_quote->version == 4)
        {
            report_body_ptr = &tdx_quote->report_body;
            report_body_size = sizeof(tdx_report_body_t);
        }
        else // version 5
        {
            tdx_quote_v5_t* v5_quote = (tdx_quote_v5_t*)tdx_quote;
            report_body_ptr = v5_quote->body;
            report_body_size = v5_quote->size;
        }

        size_t offset_to_body =
            (size_t)((uint8_t*)report_body_ptr - (uint8_t*)tdx_quote);
        size_t signed_data_size = offset_to_body + report_body_size;

        OE_CHECK_MSG(
            _ecdsa_verify(
                &attestation_key,
                tdx_quote,
                signed_data_size,
                &quote_auth_data->signature),
            "TDX report signature validation using attestation key + SHA256 "
            "ECDSA",
            NULL);
    }

    OE_TRACE_INFO("TDX quote internal verification succeeded");
    result = OE_OK;

done:
    oe_ec_public_key_free(&leaf_public_key);
    oe_ec_public_key_free(&root_public_key);
    oe_ec_public_key_free(&expected_root_public_key);
    oe_ec_public_key_free(&attestation_key);
    oe_cert_free(&leaf_cert);
    oe_cert_free(&root_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_chain_free(&pck_cert_chain);
    return result;
}
#endif // OEUTIL_TCB_ALLOW_ANY_ROOT_KEY

oe_result_t oe_get_quote_cert_chain_internal(
    const uint8_t* quote,
    const size_t quote_size,
    const uint8_t** pem_pck_certificate,
    size_t* pem_pck_certificate_size,
    oe_cert_chain_t* pck_cert_chain)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};

    if (quote == NULL || pem_pck_certificate == NULL || pck_cert_chain == NULL)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    OE_CHECK_MSG(
        _parse_quote(
            quote, quote_size, NULL, NULL, &qe_auth_data, &qe_cert_data),
        "Failed to parse quote. %s",
        oe_result_str(result));

    OE_TRACE_INFO("cert type=%d size=%d", qe_cert_data.type, qe_cert_data.size);
    *pem_pck_certificate = qe_cert_data.data;
    *pem_pck_certificate_size = qe_cert_data.size;

    // Read and validate the chain.
    OE_CHECK(oe_cert_chain_read_pem(
        pck_cert_chain, *pem_pck_certificate, *pem_pck_certificate_size));

    result = OE_OK;
done:

    return result;
}

static void _update_validity(
    oe_datetime_t* latest_from,
    oe_datetime_t* earliest_until,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    if (oe_datetime_compare(from, latest_from) > 0)
    {
        *latest_from = *from;
    }

    if (oe_datetime_compare(until, earliest_until) < 0)
    {
        *earliest_until = *until;
    }
}

oe_result_t oe_verify_sgx_quote(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* input_validation_time,
    uint32_t* verification_result)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* local_endorsements = NULL;
    size_t local_endorsements_size = 0;
    oe_sgx_endorsements_t sgx_endorsements;
    oe_tcb_info_tcb_level_t tcb_level = {0};

    if (quote == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (endorsements == NULL && input_validation_time != NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (endorsements == NULL)
    {
        OE_CHECK_MSG(
            oe_get_sgx_endorsements(
                quote,
                quote_size,
                NULL,
                0,
                (uint8_t**)&local_endorsements,
                &local_endorsements_size),
            "Failed to get SGX endorsements. %s",
            oe_result_str(result));

        endorsements = local_endorsements;
        endorsements_size = local_endorsements_size;
    }

    OE_CHECK_MSG(
        oe_parse_sgx_endorsements(
            (oe_endorsements_t*)endorsements,
            endorsements_size,
            &sgx_endorsements),
        "Failed to parse SGX endorsements.",
        oe_result_str(result));

    // Endorsements verification
    result = oe_verify_quote_with_sgx_endorsements(
        quote,
        quote_size,
        &sgx_endorsements,
        input_validation_time,
        &tcb_level,
        NULL,
        NULL);

    if (verification_result)
        *verification_result =
            oe_tcb_level_status_to_sgx_tcb_status(tcb_level.status);

done:
    if (local_endorsements)
        oe_free_sgx_endorsements(local_endorsements);

    return result;
}

oe_result_t oe_verify_quote_with_sgx_endorsements(
    const uint8_t* quote,
    size_t quote_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_datetime_t* input_validation_time,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_datetime_t* valid_from,
    oe_datetime_t* valid_until)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t get_sgx_quote_validity_result = OE_UNEXPECTED;
    oe_datetime_t validity_from = {0};
    oe_datetime_t validity_until = {0};
    oe_datetime_t validation_time = {0};

    uint32_t collateral_expiration_status;
    uint32_t quote_verification_result;
    uint8_t supplemental_data[MAX_SUPPLEMENTAL_DATA_SIZE] = {0};
    uint32_t supplemental_data_size_out = 0;
    time_t expiration_check_date;

    // quote size should fit into uint32 required by QVL/QvE
    if (quote_size > OE_UINT32_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Verify quote/endorsements for the given time.  Use endorsements
    // creation time if one was not provided.
    if (input_validation_time == NULL)
    {
        OE_CHECK_MSG(
            oe_datetime_from_string(
                (const char*)(sgx_endorsements
                                  ->items
                                      [OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME]
                                  .data),
                sgx_endorsements
                    ->items[OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME]
                    .size,
                &validation_time),
            "Invalid creation time in endorsements: %s",
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME]
                .data);
    }
    else
    {
        validation_time = *input_validation_time;
    }

    oe_datetime_log("Validation datetime: ", &validation_time);

    // Convert validation time to time_t
    OE_CHECK(oe_datetime_to_time_t(&validation_time, &expiration_check_date));

    // Try to call SGX DCAP QVL/QvE to verify quote first
    result = sgx_verify_quote(
        &_ecdsa_uuid,
        NULL,
        0,
        quote,
        (uint32_t)quote_size,
        expiration_check_date,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,
        0,
        supplemental_data,
        MAX_SUPPLEMENTAL_DATA_SIZE,
        &supplemental_data_size_out,
        *(uint32_t*)(sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_VERSION]
                         .data),
        (void*)(sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO]
                    .data),
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO].size,
        (void*)(sgx_endorsements
                    ->items[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN]
                    .data),
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN].size,
        (void*)(sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT]
                    .data),
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].size,
        (void*)(sgx_endorsements
                    ->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA]
                    .data),
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA].size,
        (void*)(sgx_endorsements
                    ->items[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT]
                    .data),
        sgx_endorsements
            ->items[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT]
            .size,
        (void*)(sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO]
                    .data),
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO].size,
        (void*)(sgx_endorsements
                    ->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
                    .data),
        sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
            .size);

    if (result != OE_PLATFORM_ERROR)
    {
        if (result != OE_OK)
        {
            OE_RAISE_MSG(
                result,
                "SGX QVL/QvE based quote verification failed with error 0x%x",
                result);
        }

        result = OE_OK;
    }

    // DCAP QVL doesn't exist or system env `SGX_DCAP_QVL` isn't set
    if (result == OE_PLATFORM_ERROR)
    {
        OE_CHECK_MSG(
            oe_verify_quote_internal(quote, quote_size),
            "Failed to verify remote quote.",
            NULL);
    }

    OE_CHECK_NO_TCB_LEVEL_MSG(
        get_sgx_quote_validity_result,
        oe_get_sgx_quote_validity(
            quote,
            quote_size,
            sgx_endorsements,
            platform_tcb_level,
            &validity_from,
            &validity_until),
        "Failed to validate quote. %s",
        oe_result_str(result));

    if (oe_datetime_compare(&validation_time, &validity_from) < 0)
    {
        char vtime[OE_DATETIME_STRING_SIZE];
        char vfrom[OE_DATETIME_STRING_SIZE];
        size_t tsize = OE_DATETIME_STRING_SIZE;
        oe_datetime_to_string(&validation_time, vtime, &tsize);
        tsize = OE_DATETIME_STRING_SIZE;
        oe_datetime_to_string(&validity_from, vfrom, &tsize);

        oe_datetime_log("Latest valid datetime: ", &validity_from);
#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
        if (_should_skip_date_check)
        {
            OE_TRACE_WARNING(
                "(Suppressed error) Validation time %s is earlier than the "
                "latest 'valid from' value %s.",
                vtime,
                vfrom);
        }
        else
        {
            OE_RAISE_MSG(
                OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
                "Validation time %s is earlier than the "
                "latest 'valid from' value %s.",
                vtime,
                vfrom);
        }
#else
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Validation time %s is earlier than the "
            "latest 'valid from' value %s.",
            vtime,
            vfrom);
#endif
    }
    if (oe_datetime_compare(&validation_time, &validity_until) > 0)
    {
        char vtime[OE_DATETIME_STRING_SIZE];
        char vuntil[OE_DATETIME_STRING_SIZE];
        size_t tsize = OE_DATETIME_STRING_SIZE;
        oe_datetime_to_string(&validation_time, vtime, &tsize);
        tsize = OE_DATETIME_STRING_SIZE;
        oe_datetime_to_string(&validity_until, vuntil, &tsize);

        oe_datetime_log("Earliest expiration datetime: ", &validity_until);
#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
        if (_should_skip_date_check)
        {
            OE_TRACE_WARNING(
                "(suppressed error) Validation time %s is later than the "
                "earliest 'valid to' value %s.",
                vtime,
                vuntil);
        }
        else
        {
            OE_RAISE_MSG(
                OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
                "Validation time %s is later than the "
                "earliest 'valid to' value %s.",
                vtime,
                vuntil);
        }
#else
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Validation time %s is later than the "
            "earliest 'valid to' value %s.",
            vtime,
            vuntil);
#endif
    }
    if (valid_from && valid_until)
    {
        *valid_from = validity_from;
        *valid_until = validity_until;
    }
    result = get_sgx_quote_validity_result;

done:

    return result;
}

oe_result_t oe_get_sgx_quote_validity(
    const uint8_t* quote,
    const size_t quote_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_datetime_t* valid_from,
    oe_datetime_t* valid_until)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t validate_revocation_list_result = OE_UNEXPECTED;

    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};
    sgx_quote_auth_data_t* quote_auth_data = NULL;

    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};

    oe_cert_t root_cert = {0};
    oe_cert_t intermediate_cert = {0};
    oe_cert_t pck_cert = {0};

    oe_datetime_t latest_from = {0};
    oe_datetime_t earliest_until = {0};
    oe_datetime_t from;
    oe_datetime_t until;

    if ((quote == NULL) || (sgx_endorsements == NULL) || (valid_from == NULL) ||
        (valid_until == NULL))
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_TRACE_INFO("Call enter %s\n", __FUNCTION__);

    OE_CHECK_MSG(
        _parse_quote(
            quote,
            quote_size,
            NULL,
            &quote_auth_data,
            &qe_auth_data,
            &qe_cert_data),
        "Failed to parse quote. %s",
        oe_result_str(result));

    pem_pck_certificate = qe_cert_data.data;
    pem_pck_certificate_size = qe_cert_data.size;

    OE_CHECK_MSG(
        oe_get_quote_cert_chain_internal(
            quote,
            quote_size,
            &pem_pck_certificate,
            &pem_pck_certificate_size,
            &pck_cert_chain),
        "Failed to retreive PCK cert chain. %s",
        oe_result_str(result));

    // Fetch certificates.
    OE_CHECK_MSG(
        oe_cert_chain_get_leaf_cert(&pck_cert_chain, &pck_cert),
        "Failed to get leaf certificate.",
        NULL);
    OE_CHECK_MSG(
        oe_cert_chain_get_root_cert(&pck_cert_chain, &root_cert),
        "Failed to get root certificate.",
        NULL);
    OE_CHECK_MSG(
        oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert),
        "Failed to get intermediate certificate.",
        NULL);

    // Process certs validity dates.
    OE_CHECK_MSG(
        oe_cert_get_validity_dates(&root_cert, &latest_from, &earliest_until),
        "Failed to get validity info from cert. %s",
        oe_result_str(result));
    OE_CHECK_MSG(
        oe_cert_get_validity_dates(&intermediate_cert, &from, &until),
        "Failed to get validity info from cert. %s",
        oe_result_str(result));
    _update_validity(&latest_from, &earliest_until, &from, &until);

    OE_CHECK_MSG(
        oe_cert_get_validity_dates(&pck_cert, &from, &until),
        "Failed to get validity info from cert. %s",
        oe_result_str(result));
    _update_validity(&latest_from, &earliest_until, &from, &until);

    // Fetch revocation info validity dates.
    OE_CHECK_NO_TCB_LEVEL_MSG(
        validate_revocation_list_result,
        oe_validate_revocation_list(
            &pck_cert, sgx_endorsements, platform_tcb_level, &from, &until),

        "Failed to validate revocation info. %s",
        oe_result_str(result));
    _update_validity(&latest_from, &earliest_until, &from, &until);

    // QE identity info validity dates.
    OE_CHECK_MSG(
        oe_validate_qe_identity(
            &quote_auth_data->qe_report_body, sgx_endorsements, &from, &until),

        "Failed quoting enclave identity checking. %s",
        oe_result_str(result));
    _update_validity(&latest_from, &earliest_until, &from, &until);

    oe_datetime_log("Quote overall issue date: ", &latest_from);
    oe_datetime_log("Quote overall next update: ", &earliest_until);
    if (oe_datetime_compare(&latest_from, &earliest_until) > 0)
    {
#ifdef OEUTIL_QUOTE_BYPASS_DATE_CHECK
        if (_should_skip_date_check)
        {
            OE_TRACE_WARNING(
                "(Suppressed error) Failed to find an overall validity period "
                "in quote.",
                NULL);
        }
        else
        {
            OE_RAISE_MSG(
                OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
                "Failed to find an overall validity period in quote.",
                NULL);
        }
#else
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Failed to find an overall validity period in quote.",
            NULL);
#endif
    }

    *valid_from = latest_from;
    *valid_until = earliest_until;

    result = validate_revocation_list_result;

done:
    oe_cert_free(&pck_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_free(&root_cert);
    oe_cert_chain_free(&pck_cert_chain);

    return result;
}
