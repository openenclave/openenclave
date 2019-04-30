// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "revocation.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/crl.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common.h"
#include "tcbinfo.h"

#ifdef OE_USE_LIBSGX

// Defaults to Intel SGX 1.8 Release Date.
oe_datetime_t _sgx_minimim_crl_tcb_issue_date = {2017, 3, 17};

oe_result_t __oe_sgx_set_minimum_crl_tcb_issue_date(
    uint32_t year,
    uint32_t month,
    uint32_t day,
    uint32_t hours,
    uint32_t minutes,
    uint32_t seconds)
{
    oe_result_t result = OE_FAILURE;
    oe_datetime_t tmp = {year, month, day, hours, minutes, seconds};

    OE_CHECK(oe_datetime_is_valid(&tmp));
    _sgx_minimim_crl_tcb_issue_date = tmp;

    result = OE_OK;
done:
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
    size_t buffer_size = 1024;
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
    size_t buffer_size = 512;
    uint8_t* buffer = oe_malloc(buffer_size);
    const char** urls = NULL;
    uint64_t num_urls = 0;
    size_t url_length = 0;

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

        // Sanity check. No URL should be this large.
        url_length = oe_strlen(urls[0]);
        if (url_length > OE_INT16_MAX)
            OE_RAISE(OE_OUT_OF_BOUNDS);

        // Add +1 to include null character.
        url_length++;

        *url = (char*)oe_malloc(url_length);
        if (*url == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(oe_memcpy_s(*url, url_length, urls[0], url_length));
        result = OE_OK;
    }

done:
    oe_free(buffer);
    return result;
}

static void _trace_datetime(const char* msg, const oe_datetime_t* date)
{
    if (get_current_logging_level() >= OE_LOG_LEVEL_INFO)
    {
        char str[21];
        size_t size = sizeof(str);
        oe_datetime_to_string(date, str, &size);
        OE_TRACE_INFO("%s%s\n", msg, str);
    }
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
    char* intermediate_crl_url = NULL;
    char* leaf_crl_url = NULL;
    oe_crl_t crls[2] = {{{0}}};
    const oe_crl_t* crl_ptrs[2] = {&crls[0], &crls[1]};
    oe_datetime_t crl_this_update_date = {0};
    oe_datetime_t crl_next_update_date = {0};

    OE_UNUSED(pck_cert_chain);

    if (intermediate_cert == NULL || leaf_cert == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_STATIC_ASSERT(
        OE_COUNTOF(crl_issuer_chain) ==
        OE_COUNTOF(revocation_args.crl_issuer_chain));

    // Gather fmspc.
    OE_CHECK(_parse_sgx_extensions(leaf_cert, &parsed_extension_info));
    OE_CHECK(oe_memcpy_s(
        revocation_args.fmspc,
        sizeof(revocation_args.fmspc),
        parsed_extension_info.fmspc,
        sizeof(parsed_extension_info.fmspc)));

    // Gather CRL distribution point URLs from certs.
    OE_CHECK(
        _get_crl_distribution_point(intermediate_cert, &intermediate_crl_url));
    OE_CHECK(_get_crl_distribution_point(leaf_cert, &leaf_crl_url));

    revocation_args.crl_urls[0] = leaf_crl_url;
    revocation_args.crl_urls[1] = intermediate_crl_url;
    revocation_args.num_crl_urls = 2;

    OE_CHECK(oe_get_revocation_info(&revocation_args));

    // Apply revocation info.
    OE_CHECK(oe_cert_chain_read_pem(
        &tcb_issuer_chain,
        revocation_args.tcb_issuer_chain,
        revocation_args.tcb_issuer_chain_size));

    // Read CRLs for each cert other than root. If any CRL is missing, the read
    // will error out.
    for (uint32_t i = 0; i < revocation_args.num_crl_urls; ++i)
    {
        OE_CHECK(oe_crl_read_der(
            &crls[i], revocation_args.crl[i], revocation_args.crl_size[i]));
        OE_CHECK(oe_cert_chain_read_pem(
            &crl_issuer_chain[i],
            revocation_args.crl_issuer_chain[i],
            revocation_args.crl_issuer_chain_size[i]));
        OE_TRACE_VERBOSE(
            "CRL certificate[%d]: \n[%s]\n",
            i,
            revocation_args.crl_issuer_chain[i]);
    }

    // Verify the leaf cert.
    // oe_cert_verify incorporates openssl -crl_check_all semantics.
    // For successful verification:
    //    1. The certificate chain must be valid. Each cert must
    //       have its issuer CA in the chain.
    //    2. Each issuer CA (ie all certs other than the leaf cert)
    //       must also have a matching CRL issued by the issuer CA.
    //    3. The certificate chain must pass signature verification.
    //    4. No certificate in the chain must be revoked.
    // Note: An issuer CA can revoke only the certs that it has issued.
    // this follows that the certificate chain and CRL issuer chains must
    // be the same. We pass the crl_issuer_chain here to assert that
    // constraint. If the crl_issuer_chain was different from the certificate
    // chain, then verification would fail because the CRLs will not be found
    // for certificates in the chain.
    OE_CHECK(oe_cert_verify(leaf_cert, &crl_issuer_chain[0], crl_ptrs, 2));

    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.sgx_tcb_comp_svn[i] =
            parsed_extension_info.comp_svn[i];
    }
    platform_tcb_level.pce_svn = parsed_extension_info.pce_svn;
    platform_tcb_level.status = OE_TCB_LEVEL_STATUS_UNKNOWN;

    OE_CHECK(oe_parse_tcb_info_json(
        revocation_args.tcb_info,
        revocation_args.tcb_info_size,
        &platform_tcb_level,
        &parsed_tcb_info));

    OE_CHECK(oe_verify_ecdsa256_signature(
        parsed_tcb_info.tcb_info_start,
        parsed_tcb_info.tcb_info_size,
        (sgx_ecdsa256_signature_t*)parsed_tcb_info.signature,
        &tcb_issuer_chain));

    // Check that the tcb has been issued after the earliest date that the
    // enclave accepts.
    if (oe_datetime_compare(
            &parsed_tcb_info.issue_date, &_sgx_minimim_crl_tcb_issue_date) != 1)
        OE_RAISE(OE_INVALID_REVOCATION_INFO);

    // Check that the CRLs have not expired.
    // The next update of the CRL must be after the earliest date that
    // the enclave accepts.
    for (uint32_t i = 0; i < OE_COUNTOF(crls); ++i)
    {
        OE_CHECK(oe_crl_get_update_dates(
            &crls[0], &crl_this_update_date, &crl_next_update_date));

        _trace_datetime("crl this update date ", &crl_this_update_date);
        _trace_datetime("crl next update date ", &crl_next_update_date);

        // CRL must be issued after minimum date.
        if (oe_datetime_compare(
                &crl_this_update_date, &_sgx_minimim_crl_tcb_issue_date) != 1)
            OE_RAISE(OE_INVALID_REVOCATION_INFO);

        // Also check that next update date is after minimum date.
        if (oe_datetime_compare(
                &crl_next_update_date, &_sgx_minimim_crl_tcb_issue_date) != 1)
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    result = OE_OK;

done:
    for (int32_t i = (int32_t)revocation_args.num_crl_urls - 1; i >= 0; --i)
    {
        oe_crl_free(&crls[i]);
    }
    for (uint32_t i = 0; i < revocation_args.num_crl_urls; ++i)
    {
        oe_cert_chain_free(&crl_issuer_chain[i]);
    }
    oe_cert_chain_free(&tcb_issuer_chain);

    oe_free(leaf_crl_url);
    oe_free(intermediate_crl_url);
    oe_cleanup_get_revocation_info_args(&revocation_args);

    return result;
}

#endif
