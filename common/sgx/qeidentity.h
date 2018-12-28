// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QE_IDENTITY_H
#define _OE_COMMON_QE_IDENTITY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/report.h>

OE_EXTERNC_BEGIN

#ifdef OE_USE_LIBSGX

oe_result_t oe_enforce_qe_identity(sgx_report_body_t* qe_report_body);

// Fetch qe identity info using the specified args structure.
oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args);

// Cleanup the args structure.
void oe_cleanup_qe_identity_info_args(oe_get_qe_identity_info_args_t* args);

void dump_info(char* title, uint8_t* data, uint8_t count);
#endif

OE_EXTERNC_END

#endif // _OE_COMMON_QE_IDENTITY_H
