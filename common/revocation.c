// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// #define OE_TRACE_LEVEL 2

#include "revocation.h"
#include <openenclave/bits/thread.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crl.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/issuedate.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "tcbinfo.h"

#ifdef OE_USE_LIBSGX

// Defaults to Unix epoch.
static oe_issue_date_t _minimim_crl_tcb_issue_date = {1970, 1, 1};

static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _date_set;

// For sgx support specifying a static.
oe_result_t __oe_sgx_set_minimum_crl_tcb_issue_date(const char* date)
{
    oe_result_t result = OE_OK;

    oe_spin_lock(&_lock);

    if (_date_set)
        OE_RAISE(OE_FAILURE);

    // Set flag early so that only one call is successful.
    _date_set = true;

    if (date == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(
        oe_issue_date_from_string(
            date, oe_strlen(date), &_minimim_crl_tcb_issue_date));

    result = OE_OK;
done:
    oe_spin_unlock(&_lock);
    return result;
}

/**
 * Parse sgx extensions from given cert.
 */
static oe_result_t _parse_sgx_extensions(
    oe_cert_t* leaf_cert,
    ParsedExtensionInfo* parsed_extension_info)
{
    oe_result_t result = OE_FAILURE;

    // The size of buffer required to parse extensions is not known beforehand.
    uint32_t buffer_size = 1024;
    uint8_t* buffer = NULL;

    buffer = (uint8_t*)oe_malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Try parsing the extensions.
    result = ParseSGXExtensions(
        leaf_cert, buffer, &buffer_size, parsed_extension_info);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        // Allocate larger buffer. extensions_buffer_size contains required size
        // of buffer.
        oe_free(buffer);
        buffer = (uint8_t*)oe_malloc(buffer_size);

        result = ParseSGXExtensions(
            leaf_cert, buffer, &buffer_size, parsed_extension_info);
    }

done:
    oe_free(buffer);
    return result;
}

typedef struct _url
{
    char str[256];
} url_t;

/**
 * Get CRL distribution points from given cert.
 */

static oe_result_t _get_crl_distribution_point(oe_cert_t* cert, char** url)
{
    oe_result_t result = OE_FAILURE;
    uint64_t buffer_size = 512;
    uint8_t* buffer = oe_malloc(buffer_size);
    const char** urls = NULL;
    uint64_t num_urls = 0;
    uint32_t url_length = 0;

    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_get_crl_distribution_points(
        cert, &urls, &num_urls, buffer, &buffer_size);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        oe_free(buffer);
        buffer = oe_malloc(buffer_size);
        if (buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        result = oe_get_crl_distribution_points(
            cert, &urls, &num_urls, buffer, &buffer_size);
    }

    if (result == OE_OK)
    {
        // At most 1 distribution point is expected.
        if (num_urls != 1)
            OE_RAISE(OE_FAILURE);
        // Include null character in length.
        url_length = oe_strlen(urls[0]) + 1;
        *url = (char*)oe_malloc(url_length);
        if (*url == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        oe_memcpy(*url, urls[0], url_length);
        result = OE_OK;
    }

done:
    oe_free(buffer);
    return result;
}

/**
 * Validate and copy buffer to enclave memory.
 */
static oe_result_t _copy_buffer_to_enclave(
    uint8_t** dst,
    uint32_t* dst_size,
    const uint8_t* src,
    uint32_t src_size)
{
    oe_result_t result = OE_FAILURE;
    if (!src || src_size == 0 || !oe_is_outside_enclave(src, src_size) ||
        dst == NULL || dst_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    *dst = oe_malloc(src_size);
    if (*dst == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    oe_memcpy(*dst, src, src_size);
    *dst_size = src_size;
    result = OE_OK;

done:
    return result;
}

/**
 * Call into host to fetch revocation information.
 */
static oe_result_t _get_revocation_info(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    uint32_t host_args_buffer_size = sizeof(*args);
    uint8_t* host_args_buffer = NULL;
    oe_get_revocation_info_args_t* host_args = NULL;
    oe_get_revocation_info_args_t tmp_args = {0};
    uint8_t* p = NULL;
    uint32_t crlUrlSizes[2] = {0};

    if (args == NULL || args->num_crl_urls != 2 || args->crl_urls[0] == NULL ||
        args->crl_urls[1] == NULL)
        OE_RAISE(OE_FAILURE);

    // Compute size of buffer to allocate in host memory to marshal the
    // arguments.
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        crlUrlSizes[i] = oe_strlen(args->crl_urls[i]) + 1;
        host_args_buffer_size += crlUrlSizes[i];
    }

    host_args_buffer = oe_host_malloc(host_args_buffer_size);
    if (host_args_buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy args struct.
    p = host_args_buffer;
    host_args = (oe_get_revocation_info_args_t*)p;
    *host_args = *args;
    p += sizeof(*host_args);

    // Copy input buffers.
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        host_args->crl_urls[i] = (const char*)p;
        oe_memcpy(p, args->crl_urls[i], crlUrlSizes[i]);
        p += crlUrlSizes[i];
    }

    OE_CHECK(
        oe_ocall(
            OE_OCALL_GET_REVOCATION_INFO,
            (uint64_t)host_args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));

    // Copy args to prevent TOCTOU issues.
    tmp_args = *host_args;

    OE_CHECK(tmp_args.result);

    if (tmp_args.host_out_buffer == NULL ||
        !oe_is_outside_enclave(tmp_args.host_out_buffer, sizeof(uint8_t)))
        OE_RAISE(OE_UNEXPECTED);

    // Ensure that all required outputs exist.
    OE_CHECK(
        _copy_buffer_to_enclave(
            &args->tcb_info,
            &args->tcb_info_size,
            tmp_args.tcb_info,
            tmp_args.tcb_info_size));
    OE_CHECK(
        _copy_buffer_to_enclave(
            &args->tcb_issuer_chain,
            &args->tcb_issuer_chain_size,
            tmp_args.tcb_issuer_chain,
            tmp_args.tcb_issuer_chain_size));

    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        OE_CHECK(
            _copy_buffer_to_enclave(
                &args->crl[i],
                &args->crl_size[i],
                tmp_args.crl[i],
                tmp_args.crl_size[i]));
        OE_CHECK(
            _copy_buffer_to_enclave(
                &args->crl_issuer_chain[i],
                &args->crl_issuer_chain_size[i],
                tmp_args.crl_issuer_chain[i],
                tmp_args.crl_issuer_chain_size[i]));
    }

    // Check for null terminators.
    if (args->tcb_info[args->tcb_info_size - 1] != 0 ||
        args->tcb_issuer_chain[args->tcb_issuer_chain_size - 1] != 0)
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        if (args->crl_issuer_chain[i][args->crl_issuer_chain_size[i] - 1] != 0)
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    result = OE_OK;
done:
    // Free args buffer and buffer allocated by host.
    if (host_args_buffer)
        oe_host_free(host_args_buffer);

    if (tmp_args.host_out_buffer)
        oe_host_free(tmp_args.host_out_buffer);

    return result;
}

static void _trace_issue_date(const char* msg, const oe_issue_date_t* date)
{
    char str[21];
    size_t size = sizeof(str);
#if (OE_TRACE_LEVEL == OE_TRACE_LEVEL_INFO)
    oe_issue_date_to_string(date, str, &size);
    OE_TRACE_INFO("%s%s\n", msg, str);
#else
    OE_UNUSED(size);
#endif
}

oe_result_t oe_enforce_revocation(
    oe_cert_t* leaf_cert,
    oe_cert_t* intermediate_cert,
    oe_cert_chain_t* pck_cert_chain)
{
    oe_result_t result = OE_FAILURE;
    ParsedExtensionInfo parsed_extension_info = {{0}};
    oe_get_revocation_info_args_t revocation_args = {0};
    oe_cert_chain_t tcb_issuer_chain = {0};
    oe_cert_chain_t crl_issuer_chain[3] = {{{0}}};
    oe_parsed_tcb_info_t parsed_tcb_info = {0};
    oe_tcb_level_t platform_tcb_level = {{0}};
    oe_verify_cert_error_t cert_verify_error = {0};
    char* intermediate_crl_url = NULL;
    char* leaf_crl_url = NULL;
    oe_crl_t crls[2] = {{{0}}};
    oe_issue_date_t tcb_info_issue_date = {0};
    oe_issue_date_t crl_next_update_date = {0};

    oe_spin_lock(&_lock);

    if (intermediate_cert == NULL || leaf_cert == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_STATIC_ASSERT(
        OE_COUNTOF(crl_issuer_chain) ==
        OE_COUNTOF(revocation_args.crl_issuer_chain));

    // Gather fmspc.
    OE_CHECK(_parse_sgx_extensions(leaf_cert, &parsed_extension_info));
    oe_memcpy(
        revocation_args.fmspc,
        parsed_extension_info.fmspc,
        sizeof(parsed_extension_info.fmspc));

    // Gather CRL distribution point URLs from certs.
    OE_CHECK(
        _get_crl_distribution_point(intermediate_cert, &intermediate_crl_url));
    OE_CHECK(_get_crl_distribution_point(leaf_cert, &leaf_crl_url));

    revocation_args.crl_urls[0] = leaf_crl_url;
    revocation_args.crl_urls[1] = intermediate_crl_url;
    revocation_args.num_crl_urls = 2;

    OE_CHECK(_get_revocation_info(&revocation_args));

    // Apply revocation info.
    OE_CHECK(
        oe_cert_chain_read_pem(
            &tcb_issuer_chain,
            revocation_args.tcb_issuer_chain,
            revocation_args.tcb_issuer_chain_size));

    for (uint32_t i = 0; i < revocation_args.num_crl_urls; ++i)
    {
        OE_CHECK(
            oe_crl_read_der(
                &crls[i], revocation_args.crl[i], revocation_args.crl_size[i]));
        OE_UNUSED(crls);
        OE_CHECK(
            oe_cert_chain_read_pem(
                &crl_issuer_chain[i],
                revocation_args.crl_issuer_chain[i],
                revocation_args.crl_issuer_chain_size[i]));
    }

    // Verify leaf and intermediate certs againt the CRL.
    OE_CHECK(
        oe_cert_verify(
            leaf_cert, &crl_issuer_chain[0], &crls[0], &cert_verify_error));

    OE_CHECK(
        oe_cert_verify(
            intermediate_cert,
            &crl_issuer_chain[1],
            &crls[1],
            &cert_verify_error));

    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.sgx_tcb_comp_svn[i] =
            parsed_extension_info.compSvn[i];
    }
    platform_tcb_level.pce_svn = parsed_extension_info.pceSvn;
    platform_tcb_level.status = OE_TCB_LEVEL_STATUS_UNKNOWN;

    OE_CHECK(
        oe_parse_tcb_info_json(
            revocation_args.tcb_info,
            revocation_args.tcb_info_size,
            &platform_tcb_level,
            &parsed_tcb_info));

    OE_CHECK(
        oe_verify_tcb_signature(
            parsed_tcb_info.tcb_info_start,
            parsed_tcb_info.tcb_info_size,
            (sgx_ecdsa256_signature_t*)parsed_tcb_info.signature,
            &tcb_issuer_chain));

    // Check that the tcb has been issued after the earliest date that the
    // enclave accepts.
    OE_CHECK(
        oe_issue_date_from_string(
            (char*)parsed_tcb_info.issue_date,
            parsed_tcb_info.issue_date_size,
            &tcb_info_issue_date));
    if (oe_issue_date_compare(
            &tcb_info_issue_date, &_minimim_crl_tcb_issue_date) != 1)
        OE_RAISE(OE_INVALID_REVOCATION_INFO);

    // Check that the CRLs have not expired.
    // The next update of the CRL must be after the earliest date that
    // the enclave accepts.
    for (uint32_t i = 0; i < OE_COUNTOF(crls); ++i)
    {
        OE_CHECK(oe_crl_get_next_update_date(&crls[0], &crl_next_update_date));

        _trace_issue_date("crl next update date ", &crl_next_update_date);
        if (oe_issue_date_compare(
                &crl_next_update_date, &_minimim_crl_tcb_issue_date) != 1)
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    result = OE_OK;

done:
    for (int32_t i = revocation_args.num_crl_urls - 1; i >= 0; --i)
    {
        oe_crl_free(&crls[i]);
        oe_free(revocation_args.crl_issuer_chain[i]);
        oe_free(revocation_args.crl[i]);
    }
    oe_free(revocation_args.tcb_issuer_chain);
    oe_free(revocation_args.tcb_info);

    for (uint32_t i = 0; i < revocation_args.num_crl_urls; ++i)
    {
        oe_cert_chain_free(&crl_issuer_chain[i]);
    }
    oe_cert_chain_free(&tcb_issuer_chain);

    oe_free(leaf_crl_url);
    oe_free(intermediate_crl_url);

    oe_spin_unlock(&_lock);

    return result;
}

#endif
