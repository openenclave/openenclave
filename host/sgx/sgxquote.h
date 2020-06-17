// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXQUOTE_H
#define _OE_SGXQUOTE_H

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

#define OE_MAX_UINT32 0xFFFFFFFF

oe_result_t oe_sgx_qe_get_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* target_info);

oe_result_t oe_sgx_qe_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size);

oe_result_t oe_sgx_qe_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote);

oe_result_t oe_sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size);

#endif // _OE_SGXQUOTE_H
