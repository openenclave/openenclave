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

/**
 * This is needed to be backwards compatible
 * with the older quote provider.
 *
 * @param[in] qe_report_body The QE report body from the quote.
 */
oe_result_t oe_validate_qe_report_body(sgx_report_body_t* qe_report_body);

/**
 * Validate the QE identity information.  Returns the validity time range
 * for the caller to validate.
 *
 * @param[in] qe_report_body The QE report body from the quote.
 * @param[in] qe_id_args The QE identity info.
 * @param[out] validity_from The date from which the QE identity info is valid.
 * @param[out] validity_until The date which the QE identity info expires.
 */
oe_result_t oe_validate_qe_identity(
    sgx_report_body_t* qe_report_body,
    oe_get_qe_identity_info_args_t* qe_id_args,
    oe_datetime_t* validity_from,
    oe_datetime_t* validity_until);

// Fetch qe identity info using the specified args structure.
oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args);

// Cleanup the args structure.
void oe_free_qe_identity_info_args(oe_get_qe_identity_info_args_t* args);

void dump_info(const char* title, const uint8_t* data, const uint8_t count);

OE_EXTERNC_END

#endif // _OE_COMMON_QE_IDENTITY_H
