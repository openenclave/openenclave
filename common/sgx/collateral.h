// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_REVOCATION_H
#define _OE_COMMON_REVOCATION_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/report.h>
#include "endorsements.h"

OE_EXTERNC_BEGIN

/**
 * Validate the revocation info.  Make sure the following:
 *
 *  1. TCB info.
 *  2. CRL.
 *
 * Are valid and returns the validity dates for the given
 * revocation info.
 *
 * @param[in] pck_cert The PCK certificate.
 * @param[in] sgx_endorsements The SGX endorsements.
 * @param[out] validity_from The date from which the revocation info is valid.
 * @param[out] validity_until The date which the revocation info expires.
 */
oe_result_t oe_validate_revocation_list(
    oe_cert_t* pck_cert,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_datetime_t* validity_from,
    oe_datetime_t* validity_until);

/**
 * Fetch quote verification collateral from the quote provider given the PCK
 * certificate and CA certificate.
 *
 * Caller is responsbile for freeing the quote verification collateral resources
 * by calling oe_free_sgx_quote_verification_collateral_args().
 *
 * @param[in] leaf_cert The PCK certificate.
 * @param[out] args Quote verification collateral.
 */
oe_result_t oe_get_sgx_quote_verification_collateral_from_certs(
    oe_cert_t* leaf_cert,
    oe_get_sgx_quote_verification_collateral_args_t* args);

/**
 * Get the quote verification collateral from the quote provider. Caller is
 * responsible for configuring the quote verification collateral input
 * parameters.
 *
 * @param[in,out] args The quote verification collateral.
 */
oe_result_t oe_get_sgx_quote_verification_collateral(
    oe_get_sgx_quote_verification_collateral_args_t* args);

/**
 * Free resources allocated by oe_get_sgx_quote_verification_collateral() and
 * oe_get_sgx_quote_verification_collateral_from_certs().
 *
 * @param[in] args The quote verification collateral.
 */
void oe_free_sgx_quote_verification_collateral_args(
    oe_get_sgx_quote_verification_collateral_args_t* args);

OE_EXTERNC_END

#endif // _OE_COMMON_REVOCATION_H
