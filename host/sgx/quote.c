// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "quote.h"
#include <assert.h>
#include <limits.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>

#include "sgxquote.h"
#include "sgxquoteprovider.h"

oe_result_t sgx_get_qetarget_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!format_id || (!opt_params && opt_params_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(target_info, 0, sizeof(sgx_target_info_t));

    // Quote workflow always begins with obtaining the target info. Therefore
    // initializing the quote provider here ensures that that we can control its
    // life time rather than Intel's attestation libraries.
    // oe_initialize_quote_provider performs initialization only once even if
    // called many times.

    OE_CHECK(oe_initialize_quote_provider());
    OE_CHECK(oe_sgx_qe_get_target_info(
        format_id, opt_params, opt_params_size, (uint8_t*)target_info));
    result = OE_OK;
done:
    return result;
}

oe_result_t sgx_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!format_id || (!opt_params && opt_params_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (quote_size)
        *quote_size = 0;

    if (!quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    result = oe_sgx_qe_get_quote_size(
        format_id, opt_params, opt_params_size, quote_size);

done:
    return result;
}

oe_result_t sgx_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* report,
    uint8_t* quote,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Reject null parameters */
    if (!report || !quote_size || !format_id ||
        (!opt_params && opt_params_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough even for quote without SigRLs */
    {
        size_t size;
        OE_CHECK(
            sgx_get_quote_size(format_id, opt_params, opt_params_size, &size));

        if (*quote_size < size)
        {
            *quote_size = size;
            OE_CHECK_NO_TRACE(OE_BUFFER_TOO_SMALL);
        }

        // Return correct size of the quote.
        *quote_size = size;
    }

    if (!quote)
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(quote, 0, *quote_size);

    /* Get the quote from the AESM service */
    result = oe_sgx_qe_get_quote(
        format_id,
        opt_params,
        opt_params_size,
        (uint8_t*)report,
        *quote_size,
        quote);

done:

    return result;
}

oe_result_t sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!format_ids && !format_ids_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    result =
        oe_sgx_get_supported_attester_format_ids(format_ids, format_ids_size);

done:
    return result;
}

oe_result_t sgx_get_supplemental_data_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint32_t* supplemental_data_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!supplemental_data_size)
        OE_RAISE(OE_INVALID_PARAMETER);
    else
        *supplemental_data_size = 0;

    result = oe_sgx_get_supplemental_data_size(
        format_id, opt_params, opt_params_size, supplemental_data_size);

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

    /* Reject null parameters */
    if (!p_quote || !p_collateral_expiration_status ||
        !p_quote_verification_result ||
        (!p_supplemental_data && supplemental_data_size > 0))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Try to get supplemental data size if needed */
    if (p_supplemental_data)
    {
        uint32_t size;

        // Don't use OE_CHECK here as this function will try to
        // detect QVL first, if QVL is not installed, we should not
        // throw error
        result = sgx_get_supplemental_data_size(
            format_id, opt_params, opt_params_size, &size);
        if (result != OE_OK)
            goto done;

        if (supplemental_data_size < size)
        {
            supplemental_data_size = size;
            OE_CHECK_NO_TRACE(OE_BUFFER_TOO_SMALL);
        }

        /* Return correct size of the supplemental data size */
        supplemental_data_size = size;
        *p_supplemental_data_size_out = size;

        memset(p_supplemental_data, 0, supplemental_data_size);
    }

    /* Verify the quote by DCAP QVL/QvE */
    result = oe_sgx_verify_quote(
        format_id,
        opt_params,
        opt_params_size,
        p_quote,
        quote_size,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        qve_report_info_size,
        p_supplemental_data,
        supplemental_data_size,
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
        qe_identity_issuer_chain_size);

    if (p_qve_report_info != NULL)
    {
        OE_TRACE_INFO(
            "SGX DCAP QvE-based quote verification is used, res: %s\n",
            oe_result_str(result));
    }
    else
    {
        OE_TRACE_INFO(
            "SGX DCAP QVL-based quote verification is used, res: %s\n",
            oe_result_str(result));
    }
done:

    return result;
}