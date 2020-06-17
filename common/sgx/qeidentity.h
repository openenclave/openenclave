// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QE_IDENTITY_H
#define _OE_COMMON_QE_IDENTITY_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/report.h>
#include "endorsements.h"

OE_EXTERNC_BEGIN

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
    const sgx_report_body_t* qe_report_body,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_datetime_t* validity_from,
    oe_datetime_t* validity_until);

OE_EXTERNC_END

#endif // _OE_COMMON_QE_IDENTITY_H
