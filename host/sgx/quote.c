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

#if defined(OE_HAS_SGX_DCAP_QL)
#include "sgxquote.h"
#include "sgxquoteprovider.h"
#endif

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

#if defined(OE_HAS_SGX_DCAP_QL)
    // Quote workflow always begins with obtaining the target info. Therefore
    // initializing the quote provider here ensures that that we can control its
    // life time rather than Intel's attestation libraries.
    // oe_initialize_quote_provider performs initialization only once even if
    // called many times.

    OE_CHECK(oe_initialize_quote_provider());
    OE_CHECK(oe_sgx_qe_get_target_info(
        format_id, opt_params, opt_params_size, (uint8_t*)target_info));
    result = OE_OK;
#else
    result = OE_UNSUPPORTED;
#endif
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

#if defined(OE_HAS_SGX_DCAP_QL)
    result = oe_sgx_qe_get_quote_size(
        format_id, opt_params, opt_params_size, quote_size);
#else
    result = OE_UNSUPPORTED;
#endif

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

#if defined(OE_HAS_SGX_DCAP_QL)
    result = oe_sgx_qe_get_quote(
        format_id,
        opt_params,
        opt_params_size,
        (uint8_t*)report,
        *quote_size,
        quote);
#else
    result = OE_UNSUPPORTED;
#endif

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

#if defined(OE_HAS_SGX_DCAP_QL)
    result =
        oe_sgx_get_supported_attester_format_ids(format_ids, format_ids_size);
#else
    // No supported format ID
    *format_ids_size = 0;
    result = OE_OK;
#endif

done:
    return result;
}
