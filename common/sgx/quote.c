// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "quote.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/crypto/ec.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "collateral.h"
#include "endorsements.h"
#include "qeidentity.h"

#include <time.h>

// Public key of Intel's root certificate.
static const char* g_expected_root_certificate_key =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
    "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
    "-----END PUBLIC KEY-----\n";

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
    const uint8_t* const quote_end = quote + quote_size;

    if (quote_end < p)
        // Pointer wrapped around.
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parsing error.  Pointer wrapper around.",
            NULL);

    *sgx_quote = NULL;

    *sgx_quote = (sgx_quote_t*)p;
    p += sizeof(sgx_quote_t);
    if (p > quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing SGX quote, before signature.",
            NULL);

    if (p + (*sgx_quote)->signature_len != quote_end)
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "Parse error after parsing SGX signature.",
            NULL);

    *quote_auth_data = (sgx_quote_auth_data_t*)(*sgx_quote)->signature;
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
        _validate_sgx_quote(*sgx_quote), "SGX quote validation failed.", NULL);

    OE_CHECK_MSG(
        _validate_qe_cert_data(qe_cert_data),
        "Failed to validate QE certificate data.",
        NULL);

    result = OE_OK;
done:
    return result;
}

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
                (const uint8_t*)g_expected_root_certificate_key,
                oe_strlen(g_expected_root_certificate_key) + 1),
            "Failed to read expected root cert key.",
            NULL);
        OE_CHECK_MSG(
            oe_ec_public_key_equal(
                &root_public_key, &expected_root_public_key, &key_equal),
            "Failed to compare keys.",
            NULL);
        if (!key_equal)
            OE_RAISE_MSG(
                OE_QUOTE_VERIFICATION_ERROR,
                "Failed to verify root public key.",
                NULL);
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

oe_result_t oe_get_quote_cert_chain_internal(
    const uint8_t* quote,
    const size_t quote_size,
    const uint8_t** pem_pck_certificate,
    size_t* pem_pck_certificate_size,
    oe_cert_chain_t* pck_cert_chain)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_quote_t* sgx_quote = NULL;
    sgx_quote_auth_data_t* quote_auth_data = NULL;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};

    if (quote == NULL || pem_pck_certificate == NULL || pck_cert_chain == NULL)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

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
    oe_datetime_t* input_validation_time)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* local_endorsements = NULL;
    size_t local_endorsements_size = 0;
    oe_sgx_endorsements_t sgx_endorsements;

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
    OE_CHECK(oe_verify_quote_with_sgx_endorsements(
        quote, quote_size, &sgx_endorsements, input_validation_time));

    result = OE_OK;

done:
    if (local_endorsements)
        oe_free_sgx_endorsements(local_endorsements);

    return result;
}

oe_result_t oe_verify_quote_with_sgx_endorsements(
    const uint8_t* quote,
    size_t quote_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_datetime_t* input_validation_time)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_datetime_t validity_from = {0};
    oe_datetime_t validity_until = {0};
    oe_datetime_t validation_time = {0};

    OE_CHECK_MSG(
        oe_verify_quote_internal(quote, quote_size),
        "Failed to verify remote quote.",
        NULL);

    OE_CHECK_MSG(
        oe_get_sgx_quote_validity(
            quote,
            quote_size,
            sgx_endorsements,
            &validity_from,
            &validity_until),
        "Failed to validate quote. %s",
        oe_result_str(result));

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
    if (oe_datetime_compare(&validation_time, &validity_from) < 0)
    {
        char vtime[OE_DATETIME_STRING_SIZE];
        char vfrom[OE_DATETIME_STRING_SIZE];
        size_t tsize = OE_DATETIME_STRING_SIZE;
        oe_datetime_to_string(&validation_time, vtime, &tsize);
        tsize = OE_DATETIME_STRING_SIZE;
        oe_datetime_to_string(&validity_from, vfrom, &tsize);

        oe_datetime_log("Latest valid datetime: ", &validity_from);
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Validation time %s is earlier than the "
            "latest 'valid from' value %s.",
            vtime,
            vfrom);
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
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Validation time %s is later than the "
            "earliest 'valid to' value %s.",
            vtime,
            vuntil);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_sgx_quote_validity(
    const uint8_t* quote,
    const size_t quote_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_datetime_t* valid_from,
    oe_datetime_t* valid_until)
{
    oe_result_t result = OE_UNEXPECTED;

    sgx_quote_t* sgx_quote = NULL;
    sgx_quote_auth_data_t* quote_auth_data = NULL;
    sgx_qe_auth_data_t qe_auth_data = {0};
    sgx_qe_cert_data_t qe_cert_data = {0};

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
            &sgx_quote,
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
    OE_CHECK_MSG(
        oe_validate_revocation_list(&pck_cert, sgx_endorsements, &from, &until),

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
        OE_RAISE_MSG(
            OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD,
            "Failed to find an overall validity period in quote.",
            NULL);

    *valid_from = latest_from;
    *valid_until = earliest_until;

    result = OE_OK;

done:
    oe_cert_free(&pck_cert);
    oe_cert_free(&intermediate_cert);
    oe_cert_free(&root_cert);
    oe_cert_chain_free(&pck_cert_chain);

    return result;
}
