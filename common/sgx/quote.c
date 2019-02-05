// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "quote.h"
#include <openenclave/internal/cert.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "qeidentity.h"
#include "revocation.h"

#ifdef OE_USE_LIBSGX

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
    {
        // Pointer wrapped around.
        OE_RAISE(OE_REPORT_PARSE_ERROR);
    }

    *sgx_quote = NULL;

    *sgx_quote = (sgx_quote_t*)p;
    p += sizeof(sgx_quote_t);
    if (p > quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    if (p + (*sgx_quote)->signature_len != quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    *quote_auth_data = (sgx_quote_auth_data_t*)(*sgx_quote)->signature;
    p += sizeof(sgx_quote_auth_data_t);

    qe_auth_data->size = ReadUint16(p);
    p += 2;
    qe_auth_data->data = (uint8_t*)p;
    p += qe_auth_data->size;

    if (p > quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    qe_cert_data->type = ReadUint16(p);
    p += 2;
    qe_cert_data->size = ReadUint32(p);
    p += 4;
    qe_cert_data->data = (uint8_t*)p;
    p += qe_cert_data->size;

    if (p != quote_end)
        OE_RAISE(OE_REPORT_PARSE_ERROR);

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

oe_result_t VerifyQuoteImpl(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* pem_pck_certificate,
    size_t pem_pck_certificate_size,
    const uint8_t* pck_crl,
    size_t pck_crl_size,
    const uint8_t* tcb_info_json,
    size_t tcb_info_json_size)
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

    OE_UNUSED(pck_crl);
    OE_UNUSED(pck_crl_size);
    OE_UNUSED(tcb_info_json);
    OE_UNUSED(tcb_info_json_size);

    OE_CHECK(_parse_quote(
        quote,
        quote_size,
        &sgx_quote,
        &quote_auth_data,
        &qe_auth_data,
        &qe_cert_data));

    if (sgx_quote->version != OE_SGX_QUOTE_VERSION)
    {
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "Unexpected quote version sgx_quote->version=%d",
            sgx_quote->version);
    }

    // The certificate provided in the quote is preferred.
    if (qe_cert_data.type == OE_SGX_PCK_ID_PCK_CERT_CHAIN)
    {
        if (qe_cert_data.size == 0)
            OE_RAISE(OE_FAILURE);
        pem_pck_certificate = qe_cert_data.data;
        pem_pck_certificate_size = qe_cert_data.size;
    }
    else
    {
        OE_RAISE_MSG(
            OE_MISSING_CERTIFICATE_CHAIN,
            "Unexpected certificate type (qe_cert_data.type=%d)",
            qe_cert_data.type);
    }

    if (pem_pck_certificate == NULL)
        OE_RAISE_MSG(
            OE_MISSING_CERTIFICATE_CHAIN, "No certificate found", NULL);

    // PckCertificate Chain validations.
    {
        // Read and validate the chain.
        OE_CHECK(oe_cert_chain_read_pem(
            &pck_cert_chain, pem_pck_certificate, pem_pck_certificate_size));

        // Fetch leaf and root certificates.
        OE_CHECK(oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert));
        OE_CHECK(oe_cert_chain_get_root_cert(&pck_cert_chain, &root_cert));
        OE_CHECK(
            oe_cert_chain_get_cert(&pck_cert_chain, 1, &intermediate_cert));

        OE_CHECK(oe_cert_get_ec_public_key(&leaf_cert, &leaf_public_key));
        OE_CHECK(oe_cert_get_ec_public_key(&root_cert, &root_public_key));

        // Ensure that the root certificate matches root of trust.
        OE_CHECK(oe_ec_public_key_read_pem(
            &expected_root_public_key,
            (const uint8_t*)g_expected_root_certificate_key,
            strlen(g_expected_root_certificate_key) + 1));

        OE_CHECK(oe_ec_public_key_equal(
            &root_public_key, &expected_root_public_key, &key_equal));
        if (!key_equal)
            OE_RAISE(OE_VERIFY_FAILED);

        OE_CHECK_MSG(
            oe_enforce_revocation(
                &leaf_cert, &intermediate_cert, &pck_cert_chain),
            "enforcing CRL",
            NULL);
    }

    // Quote validations.
    {
        // Verify SHA256 ECDSA (qe_report_body_signature, qe_report_body,
        // PckCertificate.pub_key)
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
        {
            OE_CHECK(oe_sha256_update(
                &sha256_ctx, qe_auth_data.data, qe_auth_data.size));
        }
        OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

        if (!oe_constant_time_mem_equal(
                &sha256,
                &quote_auth_data->qe_report_body.report_data,
                sizeof(sha256)))
            OE_RAISE(OE_VERIFY_FAILED);

        // Verify SHA256 ECDSA (attestation_key, SGX_QUOTE_SIGNED_DATA,
        // signature)
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

    // Quoting Enclave validations.
    OE_CHECK_MSG(
        oe_enforce_qe_identity(&quote_auth_data->qe_report_body),
        "Quoting enclave identity checking",
        NULL);
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

#else

oe_result_t VerifyQuoteImpl(
    const uint8_t* enc_quote,
    size_t quote_size,
    const uint8_t* enc_pem_pck_certificate,
    size_t pem_pck_certificate_size,
    const uint8_t* enc_pck_crl,
    size_t enc_pck_crl_size,
    const uint8_t* enc_tcb_info_json,
    size_t enc_tcb_info_json_size)
{
    OE_UNUSED(enc_quote);
    OE_UNUSED(quote_size);
    OE_UNUSED(enc_pem_pck_certificate);
    OE_UNUSED(pem_pck_certificate_size);
    OE_UNUSED(enc_pck_crl);
    OE_UNUSED(enc_pck_crl_size);
    OE_UNUSED(enc_tcb_info_json);
    OE_UNUSED(enc_tcb_info_json_size);

    return OE_UNSUPPORTED;
}
#endif
