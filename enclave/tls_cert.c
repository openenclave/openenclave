// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
 #include <openenclave/bits/defs.h>
 #include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/cert.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/print.h>
// clang-format on

#include <stdio.h>
#include "../common/common.h"
#include "ec.h"
#include "key.h"
#include "rsa.h"

// Todo: consider set CN with enclave's MRENCLAVE values
#define ISSUER_NAME "CN=Open Enclave SDK,O=OESDK TLS,C=US"
#define SUBJECT_NAME ISSUER_NAME
#define DATE_NOT_VALID_BEFORE "20190501000000"
#define DATE_NOT_VALID_AFTER "20501231235959"

static const unsigned char oid_oe_report[] = X509_OID_FOR_QUOTE_EXT;

oe_result_t calc_sha256(uint8_t* buf, size_t buf_size, OE_SHA256* sha256)
{
    oe_result_t result = OE_FAILURE;
    oe_sha256_context_t sha256_ctx = {0};

    oe_memset_s(sha256->buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, buf, buf_size));
    OE_CHECK(oe_sha256_final(&sha256_ctx, sha256));

    result = OE_OK;
done:
    return result;
}

// Input: an issuer and subject key pair
// Output: a self-signed certificate embedded critical extension with quote
// information as its content
oe_result_t generate_x509_cert(
    uint8_t* issuer_key_buf,
    size_t issuer_key_buf_size,
    uint8_t* subject_key_buf,
    size_t subject_key_buf_size,
    uint8_t* remote_report_buf,
    size_t remote_report_buf_size,
    uint8_t** output_cert,
    size_t* output_cert_size)
{
    oe_result_t result = OE_FAILURE;
    size_t bytes_written = 0;
    uint8_t* cert_buf = NULL;
    oe_cert_config_t config = {0};

    config.issuer_key_buf = issuer_key_buf;
    config.issuer_key_buf_size = issuer_key_buf_size;
    config.subject_key_buf = subject_key_buf;
    config.subject_key_buf_size = subject_key_buf_size;
    config.subject_name = (unsigned char*)SUBJECT_NAME;
    config.issuer_name = (unsigned char*)ISSUER_NAME;
    config.date_not_valid_before = (unsigned char*)DATE_NOT_VALID_BEFORE;
    config.date_not_valid_after = (unsigned char*)DATE_NOT_VALID_AFTER;
    config.ext_data_buf = remote_report_buf;
    config.ext_data_buf_size = remote_report_buf_size;
    config.ext_oid = (char*)oid_oe_report;
    config.ext_oid_size = sizeof(oid_oe_report);

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

oe_result_t oe_gen_tls_cert(
    uint8_t* issuer_key,
    size_t issuer_key_size,
    uint8_t* subject_key,
    size_t subject_key_size,
    uint8_t** output_cert,
    size_t* output_cert_size)
{
    oe_result_t result = OE_FAILURE;
    OE_SHA256 sha256 = {0};
    uint8_t* remote_report_buf = NULL;
    size_t remote_report_buf_size = OE_MAX_REPORT_SIZE;

    OE_TRACE_VERBOSE("Calling oe_gen_tls_cert");

    // generate quote with hash(cert's subject key) and set it as report data
    OE_TRACE_VERBOSE(
        "subject_key_size=%d subject_key key =\n[%s]\n",
        subject_key_size,
        subject_key);
    calc_sha256(subject_key, subject_key_size, &sha256);
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

    result = generate_x509_cert(
        issuer_key,
        issuer_key_size,
        subject_key,
        subject_key_size,
        remote_report_buf,
        remote_report_buf_size,
        output_cert,
        output_cert_size);
    OE_CHECK_MSG(
        result, "generate_x509_cert failed : %s", oe_result_str(result));

    OE_TRACE_VERBOSE("self-signed certificat size = %d", *output_cert_size);
    result = OE_OK;
done:
    oe_free_report(remote_report_buf);
    return result;
}

void oe_free_tls_cert(uint8_t* cert)
{
    if (cert)
    {
        OE_TRACE_VERBOSE("Calling oe_free_tls_cert=0x%p", cert);
        oe_free(cert);
    }
}
