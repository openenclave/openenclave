// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "quote.h"
#include <openenclave/internal/raise.h>
#include "../sgx/sgxquote.h" /* Depend on the same quote provider as SGX */

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

    if (p_supplemental_data && !p_supplemental_data_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Try to get supplemental data size if needed */
    if (p_supplemental_data)
    {
        uint32_t version = 0;
        uint32_t size = 0;

        OE_CHECK(oe_tdx_get_supplemental_data_size(
            p_quote, quote_size, &version, &size));

        if (supplemental_data_size < size)
            OE_RAISE(OE_BUFFER_TOO_SMALL);

        /* Return correct size of the supplemental data size */
        supplemental_data_size = size;
        *p_supplemental_data_size_out = size;

        memset(p_supplemental_data, 0, supplemental_data_size);
    }

    result = oe_tdx_verify_quote(
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
        p_qve_report_info,
        qve_report_info_size,
        p_supplemental_data,
        supplemental_data_size);

    if (p_qve_report_info != NULL)
    {
        OE_TRACE_INFO(
            "SGX DCAP QvE-based TDX quote verification is used, res: %s\n",
            oe_result_str(result));
    }
    else
    {
        OE_TRACE_INFO(
            "SGX DCAP QVL-based TDX quote verification is used, res: %s\n",
            oe_result_str(result));
    }

done:
    return result;
}
