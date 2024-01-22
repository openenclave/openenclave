// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tdx_verifier.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/raise.h>
#include "platform_t.h"
#include "verifier.h"

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */

oe_result_t _oe_verify_tdx_quote_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const void* p_endorsements,
    uint32_t endorsements_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out);

oe_result_t _oe_get_tdx_quote_verification_collateral_ocall(
    oe_result_t* _retval,
    const void* p_quote,
    uint32_t quote_size,
    tdx_quote_collateral_t* collateral);

oe_result_t _oe_verify_tdx_quote_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const void* p_endorsements,
    uint32_t endorsements_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out)
{
    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    OE_UNUSED(p_quote);
    OE_UNUSED(quote_size);
    OE_UNUSED(p_endorsements);
    OE_UNUSED(endorsements_size);
    OE_UNUSED(expiration_check_date);
    OE_UNUSED(p_collateral_expiration_status);
    OE_UNUSED(p_quote_verification_result);
    OE_UNUSED(p_qve_report_info);
    OE_UNUSED(qve_report_size);
    OE_UNUSED(p_supplemental_data);
    OE_UNUSED(supplemental_data_size);
    OE_UNUSED(p_supplemental_data_size_out);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_verify_tdx_quote_ocall, oe_verify_tdx_quote_ocall);

oe_result_t _oe_get_tdx_quote_verification_collateral_ocall(
    oe_result_t* _retval,
    const void* p_quote,
    uint32_t quote_size,
    tdx_quote_collateral_t* collateral)
{
    OE_UNUSED(p_quote);
    OE_UNUSED(quote_size);
    OE_UNUSED(collateral);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_get_tdx_quote_verification_collateral_ocall,
    oe_get_tdx_quote_verification_collateral_ocall);

oe_result_t tdx_verify_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const uint8_t* p_quote,
    uint32_t quote_size,
    const uint8_t* p_endorsements,
    uint32_t endorsements_size,
    time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out)
{
    // delegate input validation to host/sgx/sgxquote.c:oe_tdx_verify_quote

    oe_result_t result = OE_UNEXPECTED;
    sgx_nonce_t nonce = {0};
    uint16_t qve_isvsvn_threshold = 3;
    oe_result_t retval = OE_UNEXPECTED;

    sgx_ql_qe_report_info_t* p_qve_report_info_internal = p_qve_report_info;

    if (!p_qve_report_info)
        OE_CHECK(oe_create_qve_report_info(
            &p_qve_report_info_internal, &qve_report_info_size, &nonce));

    OE_CHECK(oe_verify_tdx_quote_ocall(
        &retval,
        format_id,
        opt_params,
        opt_params_size,
        p_quote,
        quote_size,
        p_endorsements,
        endorsements_size,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info_internal,
        qve_report_info_size,
        p_supplemental_data,
        supplemental_data_size,
        p_supplemental_data_size_out));

    result = (oe_result_t)retval;

    if (result != OE_PLATFORM_ERROR)
    {
        if (result != OE_OK)
        {
            OE_RAISE_MSG(
                result,
                "TDX QvE-based quote verification failed with error 0x%x",
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
                "Nonce during TDX quote verification has been tampered with.\n",
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
    oe_free(p_qve_report_info_internal);
    return result;
}

oe_result_t oe_get_tdx_quote_verification_collateral(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint8_t** pp_quote_collateral,
    uint32_t* p_collateral_size)
{
    tdx_quote_collateral_t collateral = {0};
    oe_result_t result = OE_FAILURE;

    if (!p_quote || !quote_size || !pp_quote_collateral || !p_collateral_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_tdx_quote_verification_collateral_ocall(
        &result, p_quote, quote_size, &collateral));

    OE_CHECK(result);

    *pp_quote_collateral = collateral.data;
    *p_collateral_size = collateral.size;

done:
    return result;
}

oe_result_t oe_free_tdx_quote_verification_collateral(
    uint8_t* p_quote_collateral)
{
    oe_free(p_quote_collateral);

    return OE_OK;
}
