// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#if defined(OE_LINK_SGX_DCAP_QL)

#include "sgxquote.h"
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>
#include <sgx_dcap_ql_wrapper.h>
#include <string.h>

// Check consistency with OE definition.
OE_STATIC_ASSERT(sizeof(sgx_target_info_t) == 512);
OE_STATIC_ASSERT(sizeof(sgx_report_t) == 432);

oe_result_t oe_sgx_qe_get_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* target_info)
{
    oe_result_t result = OE_FAILURE;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

    err = sgx_qe_get_target_info((sgx_target_info_t*)target_info);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size)
{
    oe_result_t result = OE_FAILURE;
    uint32_t* local_quote_size = (uint32_t*)quote_size;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

    err = sgx_qe_get_quote_size(local_quote_size);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote)
{
    oe_result_t result = OE_FAILURE;
    uint32_t local_quote_size = 0;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

    if (quote_size > OE_MAX_UINT32)
        OE_RAISE(OE_INVALID_PARAMETER);

    local_quote_size = (uint32_t)quote_size;

    err = sgx_qe_get_quote((sgx_report_t*)report, local_quote_size, quote);
    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);
    OE_TRACE_INFO("quote_size=%d", local_quote_size);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size)
{
    const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};
    oe_result_t result = OE_FAILURE;

    if (!format_ids_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Case when DCAP is used
    if (!format_ids || *format_ids_size < sizeof(oe_uuid_t))
    {
        *format_ids_size = sizeof(oe_uuid_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }
    memcpy(format_ids, &_ecdsa_uuid, sizeof(oe_uuid_t));
    *format_ids_size = sizeof(oe_uuid_t);

    result = OE_OK;

done:
    return result;
}

#endif
