// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
//#include <openenclave/internal/enclavelibc.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/sha.h>
#include "../common/common.h"

// Using mbedtls to create an extended X.509 certificate
#include "mbedtls_corelibc_defs.h"

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include "mbedtls_corelibc_undef.h"

// need to define a new report OID
static unsigned char oid_oe_report[] =
    {0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x01};
static int _extract_x509_extension(
    uint8_t* ext3_data,
    size_t exts_data_len,
    const uint8_t* report_oid,
    size_t report_oid_len,
    uint8_t** report_data,
    size_t* report_data_size)
{
    int ret = 1;
    unsigned char* p = NULL;
    const unsigned char* end = NULL;
    mbedtls_x509_buf oid = {0, 0, NULL};
    size_t len = 0;

    // TODO:
    // Should make this extension a critical one!

    p = (unsigned char*)ext3_data + 83; // need to find out why it;s 83!
    end = p + exts_data_len;

    // Search for target report OID
    while (p < end)
    {
        // Get extension OID ID
        if ((ret = mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID)) !=
            0)
            return (MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);

        if (oid.len == report_oid_len)
        {
            oid.tag = MBEDTLS_ASN1_OID;
            oid.p = p;

            if (0 == memcmp(oid.p, report_oid, report_oid_len))
            {
                p += report_oid_len;
                // Read the octet string tag, length encoded in two bytes
                ret = mbedtls_asn1_get_tag(
                    &p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
                if (ret)
                {
                    OE_TRACE_ERROR("ret=%d", ret);
                    goto done;
                }
                *report_data = p;
                *report_data_size = len;
                OE_TRACE_INFO("report_data_size = %d", *report_data_size);
                OE_TRACE_INFO(
                    "report_data = %p report_data[0]=0x%x  report_data_size=%d",
                    *report_data,
                    **report_data,
                    *report_data_size);
                ret = 0;
                break;
            }
        }
        *p += oid.len;
    }
done:
    if (ret)
        OE_TRACE_ERROR("Expected x509 report extension not found");

    return ret;
}

static oe_result_t extract_x509_report_extension(
    mbedtls_x509_crt* cert,
    uint8_t** report_data,
    size_t* report_data_size)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;

    ret = _extract_x509_extension(
        cert->v3_ext.p,
        cert->v3_ext.len,
        oid_oe_report,
        sizeof(oid_oe_report),
        report_data,
        report_data_size);
    if (ret)
        OE_RAISE(OE_FAILURE, "ret = %d", ret);

    OE_TRACE_INFO(
        "report_data = %p report_data[0]=0x%x report_data_size=%d",
        *report_data,
        **report_data,
        *report_data_size);
    result = OE_OK;

done:
    return result;
}

// verify report data against peer certificate
oe_result_t verify_report_user_data(
    mbedtls_x509_crt* cert,
    uint8_t* report_data)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
    uint8_t pk_buf[OE_RSA_KEY_BUFF_SIZE];
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256;

    oe_memset_s(pk_buf, sizeof(pk_buf), 0, sizeof(pk_buf));
    ret = mbedtls_pk_write_pubkey_pem(&cert->pk, pk_buf, sizeof(pk_buf));
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    OE_TRACE_INFO("pk_buf=[%s]", pk_buf);
    OE_TRACE_INFO("oe_strlen(pk_buf)=[%d]", oe_strlen((const char*)pk_buf));

    OE_TRACE_VERBOSE("public key from the peer certificate =\n[%s]", pk_buf);
    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(
        &sha256_ctx,
        pk_buf,
        oe_strlen((const char*)pk_buf) + 1)); // +1 for the ending null char
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    // validate report's user data, which contains hash(public key)
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

    OE_TRACE_INFO("Report user data validation passed");
    result = OE_OK;
done:
    return result;
}

oe_result_t verify_cert_signature(mbedtls_x509_crt* cert)
{
    oe_result_t result = OE_FAILURE;
    uint32_t flags = 0;
    int ret = 0;

    ret = mbedtls_x509_crt_verify(cert, cert, NULL, NULL, &flags, NULL, NULL);
    if (ret)
    {
        oe_verify_cert_error_t error;
        mbedtls_x509_crt_verify_info(error.buf, sizeof(error.buf), "", flags);
        OE_RAISE_MSG(
            OE_FAILURE,
            "mbedtls_x509_crt_verify failed with %s (flags=0x%x)",
            error.buf,
            flags);
    }
    OE_TRACE_INFO("certificate signature verified");
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_verify_tls_cert(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_enclave_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_report_t parsed_report = {0};
    int ret;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    // create a mbedtls cert object from encoded cert data in DER format
    ret = mbedtls_x509_crt_parse(&cert, cert_in_der, cert_in_der_len);
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    // validate the certificate signature
    result = verify_cert_signature(&cert);
    OE_CHECK(result);

    OE_CHECK(extract_x509_report_extension(&cert, &report, &report_size));

    OE_TRACE_INFO("extract_x509_report_extension() succeeded");
    OE_TRACE_INFO(
        "report = %p report[0]=0x%x report_size=%d",
        report,
        *report,
        report_size);

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now

    result = oe_verify_report(report, report_size, &parsed_report);
    OE_CHECK(result);
    OE_TRACE_INFO("oe_verify_report() succeeded");

    // verify report size and type
    if (parsed_report.size != sizeof(oe_report_t))
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "Unexpected parsed_report.size: %d (expected value:%d) ",
            parsed_report.size,
            sizeof(oe_report_t));

    if (parsed_report.type != OE_ENCLAVE_TYPE_SGX)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "Report type is not supported: parsed_report.type (%d)",
            parsed_report.type);

    // verify report's user data
    result = verify_report_user_data(&cert, parsed_report.report_data);
    OE_CHECK(result);

    // callback to the caller to verity enclave identity
    if (enclave_identity_callback)
    {
        result = enclave_identity_callback(&parsed_report.identity, arg);
        OE_CHECK(result);
        OE_TRACE_INFO("enclave_identity_callback() succeeded");
    }
    else
    {
        OE_TRACE_WARNING(
            "No enclave_identity_callback provided in oe_verify_tls_cert call",
            NULL);
    }
done:
    mbedtls_x509_crt_free(&cert);
    return result;
}