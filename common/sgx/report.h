// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_SGX_REPORT_H
#define _OE_COMMON_SGX_REPORT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include "../common.h"

OE_EXTERNC_BEGIN

oe_result_t oe_parse_sgx_report_body(
    const sgx_report_body_t* report_body,
    bool remote,
    oe_report_t* parsed_report);

OE_EXTERNC_END

#endif // _OE_COMMON_SGX_REPORT_H
