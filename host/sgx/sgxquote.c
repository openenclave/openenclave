// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if defined(OE_USE_LIBSGX)

#include "sgxquote.h"
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <sgx_dcap_ql_wrapper.h>

// Check consistency with OE definition.
OE_STATIC_ASSERT(sizeof(sgx_target_info_t) == 512);
OE_STATIC_ASSERT(sizeof(sgx_report_t) == 432);

oe_result_t oe_sgx_qe_get_target_info(uint8_t* target_info)
{
    oe_result_t result = OE_FAILURE;
    quote3_error_t err =
        sgx_qe_get_target_info((sgx_target_info_t*)target_info);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote_size(size_t* quote_size)
{
    oe_result_t result = OE_FAILURE;
    uint32_t* local_quote_size = (uint32_t*)quote_size;
    quote3_error_t err = sgx_qe_get_quote_size(local_quote_size);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote(
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote)
{
    oe_result_t result = OE_FAILURE;
    uint32_t local_quote_size = 0;
    quote3_error_t err = 0;

    if (quote_size > OE_MAX_UINT32)
        OE_RAISE(OE_INVALID_PARAMETER);

    local_quote_size = (uint32_t)quote_size;

    err = sgx_qe_get_quote((sgx_report_t*)report, local_quote_size, quote);
    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

#endif
