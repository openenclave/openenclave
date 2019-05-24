// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/utils.h>
#include "../common/common.h"

#define KEY_BUFF_SIZE 512

static const char* oid_oe_report = X509_OID_FOR_QUOTE_STRING;

// verify report user data against peer certificate
static oe_result_t verify_report_user_data(
    uint8_t* key_buff,
    size_t key_buff_size,
    uint8_t* report_data)
{
    oe_result_t result = OE_FAILURE;
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256;

    OE_TRACE_VERBOSE(
        "key_buff=[%s] \n oe_strlen(key_buff)=[%d]",
        key_buff,
        oe_strlen((const char*)key_buff));

    // create a hash of public key
    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, key_buff, key_buff_size));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    // validate report's user data against hash(public key)
    if (memcmp(report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) != 0)
    {
        for (int i = 0; i < OE_SHA256_SIZE; i++)
            OE_TRACE_VERBOSE(
                "[%d] report_data[0x%x] sha256=0x%x ",
                i,
                report_data[i],
                sha256.buf[i]);
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "hash of peer certificate's public key does not match report data",
            NULL);
    }
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_t cert = {0};
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t pub_key_buf[KEY_BUFF_SIZE];
    size_t pub_key_buf_size = KEY_BUFF_SIZE;
    oe_report_t parsed_report = {0};

    result = oe_cert_read_der(&cert, cert_in_der, cert_in_der_len);
    OE_CHECK_MSG(result, "cert_in_der_len=%d", cert_in_der_len);

    // validate the certificate signature
    result = oe_cert_verify(&cert, NULL, NULL, 0);
    OE_CHECK_MSG(
        result,
        "oe_cert_verify failed with error = %s\n",
        oe_result_str(result));

    //------------------------------------------------------------------------
    // Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now
    //------------------------------------------------------------------------

    // determine the size of the extension
    if (oe_cert_find_extension(
            &cert, (const char*)oid_oe_report, NULL, &report_size) !=
        OE_BUFFER_TOO_SMALL)
        OE_RAISE(OE_FAILURE);

    report = (uint8_t*)oe_malloc(report_size);
    if (!report)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // find the extension
    OE_CHECK(oe_cert_find_extension(
        &cert, (const char*)oid_oe_report, report, &report_size));
    OE_TRACE_VERBOSE("extract_x509_report_extension() succeeded");

#ifdef OE_BUILD_ENCLAVE
    result = oe_verify_report(report, report_size, &parsed_report);
#else
    result = oe_verify_report(NULL, report, report_size, &parsed_report);
#endif
    OE_CHECK(result);
    OE_TRACE_VERBOSE("quote validation succeeded");

    // verify report data: hash(public key)
    // extract public key from the cert
    oe_memset_s(pub_key_buf, sizeof(pub_key_buf), 0, sizeof(pub_key_buf));
    result =
        oe_cert_write_public_key_pem(&cert, pub_key_buf, &pub_key_buf_size);
    OE_CHECK(result);
    OE_TRACE_VERBOSE(
        "oe_cert_write_public_key_pem pub_key_buf_size=%d", pub_key_buf_size);

    // verify report data against peer certificate
    result = verify_report_user_data(
        pub_key_buf, pub_key_buf_size, parsed_report.report_data);
    OE_CHECK(result);
    OE_TRACE_VERBOSE("user data: hash(public key) validation passed", NULL);

    //---------------------------------------
    // call client to check enclave identity
    // --------------------------------------
    if (enclave_identity_callback)
    {
        result = enclave_identity_callback(&parsed_report.identity, arg);
        OE_CHECK(result);
        OE_TRACE_VERBOSE("enclave_identity_callback() succeeded");
    }
    else
    {
        OE_TRACE_WARNING(
            "No enclave_identity_callback provided in "
            "oe_verify_attestation_certificate call",
            NULL);
    }

done:
    oe_cert_free(&cert);
    oe_free(report);
    return result;
}
