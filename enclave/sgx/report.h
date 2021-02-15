// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_REPORT_H
#define _OE_ENCLAVE_REPORT_H

#include <openenclave/enclave.h>

void oe_handle_verify_report(uint64_t arg_in, uint64_t* arg_out);

// The input report_buffer holds a raw sgx_report_t structure.
oe_result_t oe_verify_raw_sgx_report(
    const uint8_t* report_buffer,
    size_t report_buffer_size);

// The input report holds an OE report returned by oe_get_report().
oe_result_t oe_verify_report_internal(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

#endif /* OE_ENCLAVE_REPORT_H */
