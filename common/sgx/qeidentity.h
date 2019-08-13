// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QE_IDENTITY_H
#define _OE_COMMON_QE_IDENTITY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/report.h>

OE_EXTERNC_BEGIN

oe_result_t oe_enforce_qe_identity(sgx_report_body_t* qe_report_body);

// Fetch qe identity info using the specified args structure.
oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args);

// Cleanup the args structure.
void oe_cleanup_qe_identity_info_args(oe_get_qe_identity_info_args_t* args);

void dump_info(const char* title, const uint8_t* data, const uint8_t count);

OE_EXTERNC_END

#endif // _OE_COMMON_QE_IDENTITY_H
