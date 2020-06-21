// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>

#include "../common/common.h"
#include "crypto/ec.h"
#include "crypto/key.h"
#include "crypto/rsa.h"

// Todo: consider set CN with enclave's MRENCLAVE values
#define SUBJECT_NAME "CN=Open Enclave SDK,O=OESDK TLS,C=US"
#define DATE_NOT_VALID_BEFORE "20190501000000"
#define DATE_NOT_VALID_AFTER "20501231235959"

static const unsigned char oid_oe_report[] = X509_OID_FOR_QUOTE_EXT;
static const unsigned char oid_oe_evidence[] = X509_OID_FOR_OE_EVIDENCE_EXT;

// Input: an issuer and subject key pair
// Output: a self-signed certificate embedded critical extension with quote
// information as its content
static oe_result_t generate_x509_self_signed_certificate(
    const unsigned char* oid,
    size_t oid_size,
    const unsigned char* subject_name,
    uint8_t* private_key_buf,
    size_t private_key_buf_size,
    uint8_t* public_key_buf,
    size_t public_key_buf_size,
    uint8_t* remote_report_buf,
    size_t remote_report_buf_size,
    uint8_t** output_cert,
    size_t* output_cert_size)
{
    oe_result_t result = OE_FAILURE;
    size_t bytes_written = 0;
    uint8_t* cert_buf = NULL;
    oe_cert_config_t config = {0};

    config.private_key_buf = private_key_buf;
    config.private_key_buf_size = private_key_buf_size;
    config.public_key_buf = public_key_buf;
    config.public_key_buf_size = public_key_buf_size;
    config.subject_name = (subject_name != NULL)
                              ? subject_name
                              : (const unsigned char*)SUBJECT_NAME;
    config.issuer_name = config.subject_name;
    config.date_not_valid_before = (unsigned char*)DATE_NOT_VALID_BEFORE;
    config.date_not_valid_after = (unsigned char*)DATE_NOT_VALID_AFTER;
    config.ext_data_buf = remote_report_buf;
    config.ext_data_buf_size = remote_report_buf_size;
    config.ext_oid = (char*)oid;
    config.ext_oid_size = oid_size;

    // allocate memory for cert output buffer
    cert_buf = (uint8_t*)oe_malloc(OE_MAX_CERT_SIZE);
    if (cert_buf == NULL)
        goto done;

    result = oe_gen_custom_x509_cert(
        &config, cert_buf, OE_MAX_CERT_SIZE, &bytes_written);
    OE_CHECK_MSG(
        result,
        "oe_gen_custom_x509_cert failed with %s",
        oe_result_str(result));
    OE_TRACE_VERBOSE("certificate: bytes_written = 0x%x", bytes_written);

    *output_cert_size = (size_t)bytes_written;
    *output_cert = cert_buf;
    result = OE_OK;
    cert_buf = NULL;
done:
    oe_free(cert_buf);
    return result;
}

/**
 * oe_generate_attestation_certificate.
 *
 * This function generates a self-signed x.509 certificate with an embedded
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
 * This function generates a self-signed x.509 certificate with embedded
 * evidence generated by an attester plugin for the enclave.
 *
 * @param[in] evidence_format The format UUID of the evidence to be generated.
 *
 * @param[in] subject_name a string containing an X.509 distinguished
 * name (DN) for customizing the generated certificate. This name is also used
 * as the issuer name because this is a self-signed certificate
 * See RFC5280 (https://tools.ietf.org/html/rfc5280) for details
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
oe_result_t oe_get_attestation_certificate_with_evidence(
    const oe_uuid_t* evidence_format,
    const unsigned char* subject_name,
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    uint8_t** output_cert,
    size_t* output_cert_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* evidence_buf = NULL;
    size_t evidence_buf_size = 0;

    OE_TRACE_VERBOSE("Calling oe_get_attestation_certificate_with_evidence");
    OE_TRACE_VERBOSE(
        "generate evidence with hash from public_key_size=%d public_key key "
        "=\n[%s]\n",
        public_key_size,
        public_key);

    result = oe_get_evidence(
        evidence_format,
        OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
        public_key,
        public_key_size,
        NULL,
        0,
        &evidence_buf,
        &evidence_buf_size,
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
        evidence_buf,
        evidence_buf_size,
        output_cert,
        output_cert_size);
    OE_CHECK_MSG(
        result,
        "generate_x509_self_signed_certificate failed : %s",
        oe_result_str(result));

    OE_TRACE_VERBOSE("self-signed certificate size = %d", *output_cert_size);
    result = OE_OK;
done:
    oe_free_evidence(evidence_buf);
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
