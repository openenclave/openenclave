// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/evidence.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>

#include "../common/common.h"

// Todo: consider set CN with enclave's MRENCLAVE values
#define SUBJECT_NAME "CN=Open Enclave SDK,O=OESDK TLS,C=US"
#define DATE_NOT_VALID_BEFORE "20190501000000"
#define DATE_NOT_VALID_AFTER "20501231235959"

static const unsigned char oid_oe_report[] = X509_OID_FOR_NEW_QUOTE_EXT;
static const unsigned char oid_oe_evidence[] = X509_OID_FOR_NEW_OE_EVIDENCE_EXT;
static const unsigned char oid_oe_evidence_with_inittime_claims[] =
    X509_OID_FOR_OE_EVIDENCE_WITH_INITTIME_CLAIMS_EXT;
static const unsigned char oid_oe_attestation_result[] =
    X509_OID_FOR_ATTESTATION_RESULT_EXT;

static const oe_uuid_t _uuid_sgx_local_attestation = {
    OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};

// Input: an issuer and subject key pair
// Output: a self-signed certificate embedded critical extension with quote
// information as its content
static oe_result_t generate_x509_self_signed_certificate(
    const unsigned char* oid,
    size_t oid_size,
    const unsigned char* subject_name,
    const uint8_t* private_key_buffer,
    size_t private_key_buffer_size,
    const uint8_t* public_key_buffer,
    size_t public_key_buffer_size,
    const uint8_t* oid_data_buffer,
    size_t oid_data_buffer_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size)
{
    oe_result_t result = OE_FAILURE;
    size_t bytes_written = 0;
    uint8_t* certificate_buffer = NULL;
    oe_cert_config_t config = {0};
    size_t certificate_size = 0;

    config.private_key_buf = private_key_buffer;
    config.private_key_buf_size = private_key_buffer_size;
    config.public_key_buf = public_key_buffer;
    config.public_key_buf_size = public_key_buffer_size;
    config.subject_name = (subject_name != NULL)
                              ? subject_name
                              : (const unsigned char*)SUBJECT_NAME;
    config.issuer_name = config.subject_name;
    config.date_not_valid_before = (unsigned char*)DATE_NOT_VALID_BEFORE;
    config.date_not_valid_after = (unsigned char*)DATE_NOT_VALID_AFTER;
    config.ext_data_buf = oid_data_buffer;
    config.ext_data_buf_size = oid_data_buffer_size;
    config.ext_oid = (char*)oid;
    config.ext_oid_size = oid_size;

    // allocate memory for cert output buffer and leave room for paddings
    OE_CHECK(oe_safe_add_sizet(
        oid_data_buffer_size, public_key_buffer_size, &certificate_size));
    OE_CHECK(oe_safe_add_sizet(
        certificate_size, OE_MIN_CERT_SIZE, &certificate_size));
    certificate_buffer = (uint8_t*)oe_malloc(certificate_size);
    if (!certificate_buffer)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_gen_custom_x509_cert(
        &config, certificate_buffer, certificate_size, &bytes_written);
    OE_CHECK_MSG(
        result,
        "oe_gen_custom_x509_cert failed with %s",
        oe_result_str(result));
    OE_TRACE_VERBOSE("certificate: bytes_written = 0x%x", bytes_written);

    *output_certificate_size = (size_t)bytes_written;
    *output_certificate = certificate_buffer;
    result = OE_OK;

done:
    if (result != OE_OK)
        oe_free(certificate_buffer);
    return result;
}

/**
 * oe_generate_attestation_certificate.
 *
 * This function generates a self-signed X.509 certificate with an embedded
 * quote from the underlying enclave.
 *
 * @param[in] subject_name a string contains an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) specification for details
 * Example value "CN=Open Enclave SDK,O=OESDK TLS,C=US"
 *
 * @param[in] private_key a private key used to sign this certificate
 * @param[in] private_key_size The size of the private_key buffer
 * @param[in] public_key a public key used as the certificate's subject key
 * @param[in] public_key_size The size of the public_key buffer.
 *
 * @param[out] output_cert a pointer to buffer pointer
 * @param[out] output_cert_size size of the buffer above
 *
 * @return OE_OK on success
 */
oe_result_t oe_generate_attestation_certificate(
    const unsigned char* subject_name,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t** output_cert,
    size_t* output_cert_size)
{
    oe_result_t result = OE_FAILURE;
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256 = {0};
    uint8_t* remote_report_buf = NULL;
    size_t remote_report_buf_size = OE_MAX_REPORT_SIZE;

    OE_TRACE_VERBOSE("Calling oe_generate_attestation_certificate");

    // generate quote with hash(cert's subject key) and set it as report data
    OE_TRACE_VERBOSE(
        "generate quote with hash from public_key_size=%d public_key key "
        "=\n[%s]\n",
        public_key_size,
        public_key);
    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, public_key, public_key_size));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    OE_TRACE_VERBOSE("Report data with hash of public key:");
    for (size_t i = 0; i < OE_SHA256_SIZE; i++)
        OE_TRACE_VERBOSE(
            "Report data with hash of public key[%d]=0x%x", i, sha256.buf[i]);

    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        (const uint8_t*)&sha256,
        OE_SHA256_SIZE,
        NULL,
        0,
        &remote_report_buf,
        &remote_report_buf_size);
    OE_CHECK_MSG(
        result, "oe_get_report failed with %s\n", oe_result_str(result));

    result = generate_x509_self_signed_certificate(
        oid_oe_report,
        sizeof(oid_oe_report),
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        remote_report_buf,
        remote_report_buf_size,
        output_cert,
        output_cert_size);
    OE_CHECK_MSG(
        result,
        "generate_x509_self_signed_certificate failed : %s",
        oe_result_str(result));

    OE_TRACE_VERBOSE("self-signed certificate size = %d", *output_cert_size);
    result = OE_OK;
done:
    oe_free_report(remote_report_buf);
    return result;
}

/**
 * oe_get_attestation_certificate_with_evidence.
 *
 * This function generates a self-signed X.509 certificate with embedded
 * evidence generated by an attester plugin for the enclave.
 *
 * @deprecated
 *
 * @param[in] format_id The format ID of the evidence to be generated.
 *
 * @param[in] subject_name A string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate.
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details.
 * Example value: "CN=Open Enclave SDK,O=OESDK TLS,C=US".
 *
 * @param[in] private_key A private key used to sign this certificate.
 * @param[in] private_key_size The size of the private_key buffer.
 * @param[in] public_key A public key used as the certificate's subject key.
 * @param[in] public_key_size The size of the public_key buffer.
 *
 * @param[out] output_cert A pointer to buffer pointer.
 * @param[out] output_cert_size Size of the buffer above.
 *
 * @return OE_OK on success.
 */
oe_result_t oe_get_attestation_certificate_with_evidence(
    const oe_uuid_t* format_id,
    const unsigned char* subject_name,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size)
{
    return oe_get_attestation_certificate_with_evidence_v2(
        format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        NULL,
        0,
        output_certificate,
        output_certificate_size);
}

/**
 * oe_get_attestation_certificate_with_evidence_v2
 *
 * Similar to oe_get_attestation_certificate_with_evidence, this function
 * generates a self-signed X.509 certificate with embedded evidence generated by
 * an attester plugin for the enclave, but it also allows a user to pass in
 * optional parameters.
 *
 * @experimental
 *
 * @param[in] format_id The format id of the evidence to be generated.
 *
 * @param[in] subject_name A string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate.
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details.
 * Example value: "CN=Open Enclave SDK,O=OESDK TLS,C=US"
 *
 * @param[in] private_key A private key used to sign this certificate.
 * @param[in] private_key_size The size of the private_key buffer.
 * @param[in] public_key A public key used as the certificate's subject key.
 * @param[in] public_key_size The size of the public_key buffer.
 * @param[in] optional_parameters The optional format-specific input parameters.
 * @param[in] optional_parameters_size The size of optional_parameters in bytes.
 *
 * @param[out] output_certificate A pointer to buffer pointer.
 * @param[out] output_certificate_size Size of the buffer above.
 *
 * @return OE_OK on success.
 */
oe_result_t oe_get_attestation_certificate_with_evidence_v2(
    const oe_uuid_t* format_id,
    const unsigned char* subject_name,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** output_certificate,
    size_t* output_certificate_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* evidence_buffer = NULL;
    size_t evidence_buffer_size = 0;

    OE_TRACE_VERBOSE("Calling oe_get_attestation_certificate_with_evidence_v2");
    OE_TRACE_VERBOSE(
        "generate evidence with hash from public_key_size=%d public_key key "
        "=\n[%s]\n",
        public_key_size,
        public_key);

    result = oe_get_evidence(
        format_id,
        OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
        public_key,
        public_key_size,
        optional_parameters,
        optional_parameters_size,
        &evidence_buffer,
        &evidence_buffer_size,
        NULL,
        0);
    OE_CHECK_MSG(
        result, "oe_get_evidence failed with %s\n", oe_result_str(result));

    result = generate_x509_self_signed_certificate(
        oid_oe_evidence,
        sizeof(oid_oe_evidence),
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        evidence_buffer,
        evidence_buffer_size,
        output_certificate,
        output_certificate_size);
    OE_CHECK_MSG(
        result,
        "generate_x509_self_signed_certificate failed : %s",
        oe_result_str(result));

    OE_TRACE_VERBOSE(
        "self-signed certificate size = %d", *output_certificate_size);
    result = OE_OK;
done:
    oe_free_evidence(evidence_buffer);
    return result;
}

void oe_free_attestation_certificate(uint8_t* cert)
{
    if (cert)
    {
        OE_TRACE_VERBOSE("Calling oe_free_attestation_certificate=0x%p", cert);
        oe_free(cert);
    }
}

/**
 * oe_get_passport_attestation_certificate_v1
 *
 * This function generates a self-signed X.509 certificate in DER format with
 * embedded attestation result returned by a verifier. Note that the attestation
 * result is an opaque buffer. The rule to interpret the buffer depends on the
 * agreement between the relying party and the verifier.
 *
 * @experimental
 *
 * @param[in] subject_name A string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate.
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details.
 * Example value "CN=Open Enclave SDK,O=OESDK TLS,C=US"
 * @param[in] private_key A private key used to sign this certificate.
 * @param[in] private_key_size The size of the buffer above.
 * @param[in] public_key A public key used as the certificate's subject key.
 * @param[in] public_key_size The size of the buffer above.
 * @param[in] attestation_result_buffer An flat buffer representing the
 * attestation results from a verifier.
 * @param[in] attestation_result_buffer_size The size of the buffer above in
 * bytes.
 * @param[out] output_certificate_in_der A pointer to buffer pointer.
 * @param[out] output_certificate_size The pointer to the size of the buffer
 * above.
 *
 * @retval OE_OK The operation was successful.
 * @retval OE_INVALID_PARAMETER One or more invalid parameters.
 * @retval Other appropriate error code.
 */
oe_result_t oe_get_passport_attestation_certificate_v1(
    const unsigned char* subject_name,
    const uint8_t* private_key,
    size_t private_key_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* attestation_result_buffer,
    size_t attestation_result_buffer_size,
    uint8_t** output_certificate_in_der,
    size_t* output_certificate_in_der_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* certificate_in_der = NULL;
    size_t certificate_in_der_size = 0;

    OE_TRACE_VERBOSE("Calling oe_get_passport_attestation_certificate_v1");

    if (!private_key || !private_key_size || !public_key || !public_key_size ||
        !attestation_result_buffer || !attestation_result_buffer_size ||
        !output_certificate_in_der || !output_certificate_in_der_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    *output_certificate_in_der = NULL;
    *output_certificate_in_der_size = 0;

    result = generate_x509_self_signed_certificate(
        oid_oe_attestation_result,
        sizeof(oid_oe_attestation_result),
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        attestation_result_buffer,
        attestation_result_buffer_size,
        &certificate_in_der,
        &certificate_in_der_size);
    OE_CHECK_MSG(
        result,
        "generate_x509_self_signed_certificate failed : %s",
        oe_result_str(result));

    OE_TRACE_VERBOSE("passport certificate size = %d", certificate_in_der_size);

    *output_certificate_in_der = certificate_in_der;
    *output_certificate_in_der_size = certificate_in_der_size;

    result = OE_OK;

done:
    return result;
}

/**
 * oe_get_background_check_attestation_certificate_v1
 *
 * This function generates a self-signed X.509 certificate in DER format with
 * embedded evidence generated by an attester plugin for the enclave. In
 * addition, it allows an application to optionally pass in run-time custom
 * claims and init-time custom claims.
 *
 * @experimental
 *
 * @param[in] format_id The format id of the evidence to be generated.
 * Supported: OE_FORMAT_UUID_SGX_ECDSA and OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION.
 * @param[in] subject_name A string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate.
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details.
 * Example value "CN=Open Enclave SDK,O=OESDK TLS,C=US"
 * @param[in] private_key A private key used to sign this certificate.
 * @param[in] private_key_size The size of the buffer above.
 * @param[in] public_key A public key used as the certificate's subject key.
 * @param[in] public_key_size The size of the buffer above.
 * @param[in] inittime_custom_claims_buffer An optional flat buffer representing
 * the init-time custom claims.
 * @param[in] inittime_custom_claims_buffer_size The size of the buffer above in
 * bytes.
 * @param[in] runtime_custom_claims_buffer An optional flat buffer representing
 * the run-time cutom claims.
 * @param[in] runtime_custom_claims_buffer_size The size of the buffer above in
 * bytes.
 * @param[in] optional_parameters The optional format-specific input parameters.
 * @param[in] optional_parameters_size The size of buffer above in bytes.
 * @param[out] output_certificate_in_der A pointer to buffer pointer.
 * @param[out] output_certificate_size The pointer to the size of the buffer
 * above.
 *
 * @retval OE_OK The operation was successful.
 * @retval OE_INVALID_PARAMETER One or more invalid parameters.
 * @retval OE_UNSUPPORTED The format_id is unsupported.
 * @retval Other appropriate error code.
 */
oe_result_t oe_get_background_check_attestation_certificate_v1(
    const oe_uuid_t* format_id,
    const unsigned char* subject_name,
    const uint8_t* private_key,
    size_t private_key_size,
    const uint8_t* public_key,
    size_t public_key_size,
    const uint8_t* inittime_custom_claims_buffer,
    size_t inittime_custom_claims_buffer_size,
    const uint8_t* runtime_custom_claims_buffer,
    size_t runtime_custom_claims_buffer_size,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** output_certificate_in_der,
    size_t* output_certificate_in_der_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* evidence_buffer = NULL;
    size_t evidence_buffer_size = 0;
    uint8_t* certificate_in_der = NULL;
    size_t certificate_in_der_size = 0;

    OE_TRACE_VERBOSE(
        "Calling oe_get_background_check_attestation_certificate_v1");

    if (!format_id || !private_key || !private_key_size || !public_key ||
        !public_key_size || !output_certificate_in_der ||
        !output_certificate_in_der_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    *output_certificate_in_der = NULL;
    *output_certificate_in_der_size = 0;

    // Do not support legacy format and raw quote
    if (memcmp(format_id, &_uuid_sgx_local_attestation, sizeof(oe_uuid_t)) &&
        memcmp(format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t)))
        OE_RAISE(OE_UNSUPPORTED);

    result = oe_get_evidence(
        format_id,
        OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
        runtime_custom_claims_buffer,
        runtime_custom_claims_buffer_size,
        optional_parameters,
        optional_parameters_size,
        &evidence_buffer,
        &evidence_buffer_size,
        NULL,
        0);
    OE_CHECK_MSG(
        result, "oe_get_evidence failed with %s\n", oe_result_str(result));

    if (inittime_custom_claims_buffer && inittime_custom_claims_buffer_size)
    {
        size_t evidence_with_inittime_claims_size;
        OE_CHECK(oe_safe_add_sizet(
            evidence_buffer_size,
            inittime_custom_claims_buffer_size,
            &evidence_with_inittime_claims_size));
        evidence_buffer =
            oe_realloc(evidence_buffer, evidence_with_inittime_claims_size);
        if (!evidence_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);
        uint64_t inittime_custom_claims_offset;
        OE_CHECK(oe_safe_add_u64(
            (uint64_t)evidence_buffer,
            (uint64_t)evidence_buffer_size,
            &inittime_custom_claims_offset));
        OE_CHECK(oe_memcpy_s(
            (void*)inittime_custom_claims_offset,
            inittime_custom_claims_buffer_size,
            inittime_custom_claims_buffer,
            inittime_custom_claims_buffer_size));
        evidence_buffer_size = evidence_with_inittime_claims_size;
    }

    result = generate_x509_self_signed_certificate(
        oid_oe_evidence_with_inittime_claims,
        sizeof(oid_oe_evidence_with_inittime_claims),
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        evidence_buffer,
        evidence_buffer_size,
        &certificate_in_der,
        &certificate_in_der_size);
    OE_CHECK_MSG(
        result,
        "generate_x509_self_signed_certificate failed : %s",
        oe_result_str(result));

    OE_TRACE_VERBOSE(
        "backgroud-check certificate size = %d", certificate_in_der_size);

    *output_certificate_in_der = certificate_in_der;
    *output_certificate_in_der_size = certificate_in_der_size;

    result = OE_OK;

done:
    oe_free(evidence_buffer);

    return result;
}
