// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "verifier.h"
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <stdlib.h>
#include <string.h>
#include "platform_t.h"
#include "report.h"

// Hard code Intel signed QvE Identity below
// You can get such info from latest QvE Identity JSON file
// e.g., Get the QvE Identity JSON file from
// https://api.trustedservices.intel.com/sgx/certification/v2/qve/identity
//

static const uint32_t g_qve_misc_select = 0x00000000;
static const uint32_t g_qve_misc_select_mask = 0xFFFFFFFF;

static const uint64_t g_qve_attribute_flags = 0x0000000000000001;
static const uint64_t g_qve_attribute_xfrm = 0x0000000000000000;
static const uint64_t g_qve_attribute_flags_mask = 0xFFFFFFFFFFFFFFFb;
static const uint64_t g_qve_attribute_xfrm_mask = 0x0000000000000000;

static const uint8_t g_qve_mrsigner[32] = {
    0x8C, 0x4F, 0x57, 0x75, 0xD7, 0x96, 0x50, 0x3E, 0x96, 0x13, 0x7F,
    0x77, 0xC6, 0x8A, 0x82, 0x9A, 0x00, 0x56, 0xAC, 0x8D, 0xED, 0x70,
    0x14, 0x0B, 0x08, 0x1B, 0x09, 0x44, 0x90, 0xC5, 0x7B, 0xFF};

static const uint16_t QVE_PRODID = 2;

// Defense in depth, threshold must be greater or equal to least QvE ISV SVN
const uint16_t LEAST_QVE_ISVSVN = 3;

static void dump_info(
    const char* title,
    const uint8_t* data,
    const uint8_t count)
{
    OE_TRACE_INFO("%s\n", title);
    for (uint8_t i = 0; i < count; i++)
    {
        OE_TRACE_INFO("[%d] = %x\n", i, data[i]);
    }
}

#if !defined(OE_USE_BUILTIN_EDL)
/**
 * Declare the prototype of the following function to avoid the
 * missing-prototypes warning.
 */

oe_result_t _oe_verify_quote_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size);

oe_result_t _oe_verify_quote_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size)
{
    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    OE_UNUSED(p_quote);
    OE_UNUSED(quote_size);
    OE_UNUSED(expiration_check_date);
    OE_UNUSED(p_collateral_expiration_status);
    OE_UNUSED(p_quote_verification_result);
    OE_UNUSED(p_qve_report_info);
    OE_UNUSED(qve_report_size);
    OE_UNUSED(p_supplemental_data);
    OE_UNUSED(supplemental_data_size);
    OE_UNUSED(p_supplemental_data_size_out);
    OE_UNUSED(collateral_version);
    OE_UNUSED(p_tcb_info);
    OE_UNUSED(tcb_info_size);
    OE_UNUSED(p_tcb_info_issuer_chain);
    OE_UNUSED(tcb_info_issuer_chain_size);
    OE_UNUSED(p_pck_crl);
    OE_UNUSED(pck_crl_size);
    OE_UNUSED(p_root_ca_crl);
    OE_UNUSED(root_ca_crl_size);
    OE_UNUSED(p_pck_crl_issuer_chain);
    OE_UNUSED(pck_crl_issuer_chain_size);
    OE_UNUSED(p_qe_identity);
    OE_UNUSED(qe_identity_size);
    OE_UNUSED(p_qe_identity_issuer_chain);
    OE_UNUSED(qe_identity_issuer_chain_size);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_verify_quote_ocall, oe_verify_quote_ocall);
#endif

oe_result_t oe_verify_qve_report_and_identity(
    const uint8_t* p_quote,
    uint32_t quote_size,
    const sgx_ql_qe_report_info_t* p_qve_report_info,
    time_t expiration_check_date,
    uint32_t collateral_expiration_status,
    uint32_t quote_verification_result,
    const uint8_t* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint16_t qve_isvsvn_threshold)
{
    oe_result_t result = OE_UNEXPECTED;

    oe_sha256_context_t sha_handle = {0};
    OE_SHA256 report_data_hash = {0};
    sgx_report_data_t report_data = {0};
    const sgx_report_t* p_qve_report = &(p_qve_report_info->qe_report);

    if (p_quote == NULL || p_qve_report_info == NULL ||
        sizeof(*p_qve_report_info) != sizeof(sgx_ql_qe_report_info_t) ||
        !oe_is_within_enclave(p_quote, quote_size) ||
        !oe_is_within_enclave(
            p_qve_report_info, sizeof(sgx_ql_qe_report_info_t)) ||
        (p_supplemental_data == NULL && supplemental_data_size != 0) ||
        (p_supplemental_data != NULL && supplemental_data_size == 0))
        return OE_INVALID_PARAMETER;

    if (p_supplemental_data && supplemental_data_size > 0)
    {
        if (!oe_is_within_enclave(p_supplemental_data, supplemental_data_size))
        {
            return OE_INVALID_PARAMETER;
        }
    }

    // Defense in depth, threshold must be greater or equal to 3
    if (qve_isvsvn_threshold < LEAST_QVE_ISVSVN)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "Input QvE ISV SVN is not valid. Required SVN is larger or equal "
            "to 0x%08X, actual SVN 0x%08X",
            LEAST_QVE_ISVSVN,
            qve_isvsvn_threshold);
    }

    // verify QvE report
    OE_CHECK_MSG(
        oe_verify_raw_sgx_report((uint8_t*)p_qve_report, sizeof(sgx_report_t)),
        "SGX Verifier Plugin: Failed to verify QvE report. %s",
        oe_result_str(result));

    // verify QvE report data
    // report_data = SHA256([nonce || quote || expiration_check_date ||
    // expiration_status || verification_result || supplemental_data]) || 32 -
    // 0x00
    OE_CHECK(oe_sha256_init(&sha_handle));

    // nonce
    OE_CHECK(oe_sha256_update(
        &sha_handle,
        &(p_qve_report_info->nonce),
        sizeof(p_qve_report_info->nonce)));

    // quote
    OE_CHECK(oe_sha256_update(&sha_handle, p_quote, quote_size));

    // expiration_check_date
    OE_CHECK(oe_sha256_update(
        &sha_handle, &expiration_check_date, sizeof(expiration_check_date)));

    // collateral_expiration_status
    OE_CHECK(oe_sha256_update(
        &sha_handle,
        &collateral_expiration_status,
        sizeof(collateral_expiration_status)));

    // quote_verification_result
    OE_CHECK(oe_sha256_update(
        &sha_handle,
        &quote_verification_result,
        sizeof(quote_verification_result)));

    // p_supplemental_data
    if (p_supplemental_data)
    {
        OE_CHECK(oe_sha256_update(
            &sha_handle, p_supplemental_data, supplemental_data_size));
    }

    // get the hashed report_data
    OE_CHECK(oe_sha256_final(&sha_handle, &report_data_hash));

    memcpy(&report_data, &report_data_hash, sizeof(report_data_hash));

    if (memcmp(
            &p_qve_report->body.report_data,
            &report_data,
            sizeof(report_data)) != 0)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "QvE report data is not correct.",
            NULL);
    }

    // Check MiscSelect in QvE report
    if (((p_qve_report->body.miscselect) & g_qve_misc_select_mask) !=
        g_qve_misc_select)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "Expect QvE misc select = 0x%lx, msic slect mask = 0x%lx"
            "QvE report misc select = 0x%lx",
            g_qve_misc_select,
            g_qve_misc_select_mask,
            p_qve_report->body.miscselect);

        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "QvE misc select is not correct",
            NULL);
    }

    // Check Attribute in QvE report
    if (((p_qve_report->body.attributes.flags) & g_qve_attribute_flags_mask) !=
        g_qve_attribute_flags)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "Expect QvE attribute flag = 0x%lx, attributes_flag_mask = "
            "0x%lx"
            "QvE report attributes.flag = 0x%lx",
            g_qve_attribute_flags,
            g_qve_attribute_flags_mask,
            p_qve_report->body.attributes.flags);
    }

    if (((p_qve_report->body.attributes.xfrm) & g_qve_attribute_xfrm_mask) !=
        g_qve_attribute_xfrm)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "Expect QvE attribute xfrm = 0x%lx, attributes_xfrm_mask = "
            "0x%lx"
            "QvE report attributes.xfrm = 0x%lx",
            g_qve_attribute_xfrm,
            g_qve_attribute_xfrm_mask,
            p_qve_report->body.attributes.xfrm);
    }

    // Check Mrsigner in QvE report
    if (memcmp(
            &(p_qve_report->body.mrsigner),
            g_qve_mrsigner,
            sizeof(g_qve_mrsigner)) != 0)
    {
        dump_info(
            "Expected QvE mrsigner:", g_qve_mrsigner, sizeof(g_qve_mrsigner));
        dump_info(
            "Actual QvE mrsigner, qe_report_body->mrsigner:",
            p_qve_report->body.mrsigner,
            sizeof(p_qve_report->body.mrsigner));
        OE_RAISE(OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED);
    }

    // Check Prod ID in QvE report
    if (p_qve_report->body.isvprodid != QVE_PRODID)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "QvE isvprodid mismatch. Expected 0x%04X, actual 0x%04X",
            QVE_PRODID,
            p_qve_report->body.isvprodid);
    }

    // Check QvE ISV SVN in QvE report
    if (p_qve_report->body.isvsvn < qve_isvsvn_threshold)
    {
        OE_RAISE_MSG(
            OE_QUOTE_ENCLAVE_IDENTITY_VERIFICATION_FAILED,
            "QvE isvsvn is out-of-date. Required SVN is larger or equal to "
            "0x%08X, actual SVN 0x%08X",
            qve_isvsvn_threshold,
            p_qve_report->body.isvsvn);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t sgx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_nonce_t nonce = {0};
    uint8_t* p_self_report = NULL;
    size_t report_size = 0;
    sgx_target_info_t* p_self_target_info = NULL;
    size_t target_info_size = 0;
    uint16_t qve_isvsvn_threshold = 3;
    oe_result_t retval = OE_UNEXPECTED;

    sgx_ql_qe_report_info_t* p_qve_report_info_internal = p_qve_report_info;

    // Add format_id for forward compatibility
    if (!format_id || !supplemental_data_size ||
        (!opt_params && opt_params_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((p_qve_report_info &&
         (qve_report_info_size != sizeof(sgx_ql_qe_report_info_t))) ||
        (!p_qve_report_info && qve_report_info_size != 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!p_qve_report_info)
    {
        p_qve_report_info_internal = (sgx_ql_qe_report_info_t*)oe_malloc(
            sizeof(sgx_ql_qe_report_info_t));
        if (p_qve_report_info_internal == NULL)
        {
            result = OE_OUT_OF_MEMORY;
            goto done;
        }

        oe_memset_s(
            p_qve_report_info_internal,
            sizeof(sgx_ql_qe_report_info_t),
            0,
            sizeof(sgx_ql_qe_report_info_t));

        qve_report_info_size = sizeof(sgx_ql_qe_report_info_t);

        // Generate nonce
        OE_CHECK(oe_random(&nonce, 16));
        OE_CHECK(oe_memcpy_s(
            &p_qve_report_info_internal->nonce,
            sizeof(sgx_nonce_t),
            &nonce,
            sizeof(sgx_nonce_t)));

        // Try to get self target info
        OE_CHECK(
            oe_get_report(0, NULL, 0, NULL, 0, &p_self_report, &report_size));

        OE_CHECK(oe_get_target_info(
            p_self_report,
            report_size,
            (void**)(&p_self_target_info),
            &target_info_size));

        OE_CHECK(oe_memcpy_s(
            &p_qve_report_info_internal->app_enclave_target_info,
            sizeof(sgx_target_info_t),
            p_self_target_info,
            target_info_size));
    }

    OE_CHECK(oe_verify_quote_ocall(
        &retval,
        format_id,
        NULL,
        0,
        p_quote,
        quote_size,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info_internal,
        qve_report_info_size,
        p_supplemental_data,
        supplemental_data_size,
        p_supplemental_data_size_out,
        collateral_version,
        p_tcb_info,
        tcb_info_size,
        p_tcb_info_issuer_chain,
        tcb_info_issuer_chain_size,
        p_pck_crl,
        pck_crl_size,
        p_root_ca_crl,
        root_ca_crl_size,
        p_pck_crl_issuer_chain,
        pck_crl_issuer_chain_size,
        p_qe_identity,
        qe_identity_size,
        p_qe_identity_issuer_chain,
        qe_identity_issuer_chain_size));

    result = (oe_result_t)retval;

    if (result != OE_PLATFORM_ERROR)
    {
        if (result != OE_OK)
        {
            OE_RAISE_MSG(
                result,
                "SGX QvE-based quote verification failed with error 0x%x",
                result);
        }

        // Defense in depth
        if (memcmp(
                &nonce,
                &p_qve_report_info_internal->nonce,
                sizeof(sgx_nonce_t)) != 0)
        {
            OE_RAISE_MSG(
                OE_VERIFY_FAILED,
                "Nonce during SGX quote verification has been tampered with.\n",
                NULL);
        }

        // Call internal API to verify QvE identity
        OE_CHECK_MSG(
            oe_verify_qve_report_and_identity(
                p_quote,
                quote_size,
                p_qve_report_info_internal,
                expiration_check_date,
                *p_collateral_expiration_status,
                *p_quote_verification_result,
                p_supplemental_data,
                *p_supplemental_data_size_out,
                qve_isvsvn_threshold),
            "Failed to check QvE report and identity",
            oe_result_str(result));

        result = OE_OK;
    }

done:
    oe_free_target_info(p_self_target_info);
    oe_free_report(p_self_report);
    oe_free(p_qve_report_info_internal);
    return result;
}
