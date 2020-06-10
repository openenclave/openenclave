// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_REPORT_H
#define _OE_ENCLAVE_REPORT_H

#include <openenclave/enclave.h>

void oe_handle_verify_report(uint64_t arg_in, uint64_t* arg_out);

oe_result_t oe_verify_report_internal(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

#endif /* OE_ENCLAVE_REPORT_H */
