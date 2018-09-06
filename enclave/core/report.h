// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CORE_REPORT_H
#define _OE_ENCLAVE_CORE_REPORT_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/sgxtypes.h>

oe_result_t _HandleGetSgxReport(uint64_t argIn);

oe_result_t sgx_create_report(
    const void* report_data,
    size_t report_data_size,
    const void* targetInfo,
    size_t targetInfoSize,
    sgx_report_t* report);

#endif /* _OE_ENCLAVE_CORE_REPORT_H */
