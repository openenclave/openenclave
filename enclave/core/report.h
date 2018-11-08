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

/*
 * Special alignment requirement for EREPORT instruction:
 * - ti: 512-byte aligned.
 * - rd: 128-byte aligned.
 * - r:  512-byte aligned.
 */
#if defined(__linux__)

OE_INLINE void oe_issue_sgx_ereport(
    sgx_target_info_t* ti,
    sgx_report_data_t* rd,
    sgx_report_t* r)
{
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(ti), "c"(rd), "d"(r)
        : "memory");
}

#elif defined(_WIN32)

void oe_issue_sgx_ereport(
    sgx_target_info_t* ti,
    sgx_report_data_t* rd,
    sgx_report_t* r);

#else

#error("unsupported");

#endif

#endif /* _OE_ENCLAVE_CORE_REPORT_H */
