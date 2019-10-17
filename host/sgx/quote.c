// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "quote.h"
#include <assert.h>
#include <limits.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>

#if defined(OE_LINK_SGX_DCAP_QL)
#include "sgxquote.h"
#include "sgxquoteprovider.h"
#endif

oe_result_t sgx_get_qetarget_info(sgx_target_info_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    memset(target_info, 0, sizeof(sgx_target_info_t));

#if defined(OE_LINK_SGX_DCAP_QL)
    // Quote workflow always begins with obtaining the target info. Therefore
    // initializing the quote provider here ensures that that we can control its
    // life time rather than Intel's attestation libraries.
    // oe_initialize_quote_provider performs initialization only once even if
    // called many times.

    OE_CHECK(oe_initialize_quote_provider());
    OE_CHECK(oe_sgx_qe_get_target_info((uint8_t*)target_info));
    result = OE_OK;
done:
    return result;
#else
    result = OE_UNSUPPORTED;
    return result;
#endif
}

oe_result_t sgx_get_quote_size(size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (quote_size)
        *quote_size = 0;

    if (!quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(OE_LINK_SGX_DCAP_QL)
    result = oe_sgx_qe_get_quote_size(quote_size);
#else
    result = OE_UNSUPPORTED;
#endif

done:
    return result;
}

oe_result_t sgx_get_quote(
    const sgx_report_t* report,
    uint8_t* quote,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Reject null parameters */
    if (!report || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Reject if quote size not big enough even for quote without SigRLs */
    {
        size_t size;
        OE_CHECK(sgx_get_quote_size(&size));

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

#if defined(OE_LINK_SGX_DCAP_QL)
    result = oe_sgx_qe_get_quote((uint8_t*)report, *quote_size, quote);
#else
    result = OE_UNSUPPORTED;
#endif

done:

    return result;
}
