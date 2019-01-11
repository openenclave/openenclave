// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CORE_REPORT_H
#define _OE_ENCLAVE_CORE_REPORT_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/sgxtypes.h>

oe_result_t _handle_get_sgx_report(uint64_t arg_in);

oe_result_t sgx_create_report(
    const void* report_data,
    size_t report_data_size,
    const void* target_info,
    size_t target_info_size,
    sgx_report_t* report);

#endif /* _OE_ENCLAVE_CORE_REPORT_H */
