// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CORE_REPORT_H
#define _OE_ENCLAVE_CORE_REPORT_H

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>

oe_result_t _handle_get_sgx_report(uint64_t arg_in);

oe_result_t sgx_create_report(
    const void* report_data,
    size_t report_data_size,
    const void* target_info,
    size_t target_info_size,
    sgx_report_t* report);

oe_result_t oe_get_report_v2_internal(
    uint32_t flags,
    const oe_uuid_t* format_id,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

#endif /* _OE_ENCLAVE_CORE_REPORT_H */
