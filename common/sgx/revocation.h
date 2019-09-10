// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_REVOCATION_H
#define _OE_COMMON_REVOCATION_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/report.h>

OE_EXTERNC_BEGIN

/**
 * This function gets the revocation information from the given
 * PCK Cert and CA cert and does validation.
 *
 * @param[in] leaf_cert The PCK certificate.
 * @param[in] revocation_args The revocation information.
 */
oe_result_t oe_enforce_revocation(
    oe_cert_t* leaf_cert,
    oe_cert_t* intermediate_cert);

/** Validate revocation info.  Make sure the following:
 *
 *  1. TCB info.
 *  2. CRL.
 *
 * Are valid and returns the validity dates for this
 * revocation information for the caller to validate.
 *
 * @param pck_cert[in] The PCK certificate.
 * @param revocation_args[in] The revocation information.
 * @param validity_from[out] The date from which the revocation info is valid.
 * @param validity_until[out] The date which the revocation info expires.
 */
oe_result_t oe_validate_revocation_list(
    oe_cert_t* pck_cert,
    oe_get_revocation_info_args_t* revocation_args,
    oe_datetime_t* validity_from,
    oe_datetime_t* validity_until);

/**
 * Fetch revocation info for the PCK certificate and CA
 * certificate.
 *
 * Caller is responsbile for freeing the revocation info resources
 * by calling oe_free_get_revocation_info_args().
 *
 * @param leaf_cert[in] the PCK certificate.
 * @param intermediate_cert[in] the CA certificate.
 * @param args[out] the revocation info.
 */
oe_result_t oe_get_revocation_info_from_certs(
    oe_cert_t* leaf_cert,
    oe_cert_t* intermediate_cert,
    oe_get_revocation_info_args_t* args);

/**
 * Get the revocation info.  Caller is responsible for
 * configuring the revocation info input parameters.
 *
 * @param args[in/out] the revocation info.
 */
oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args);

/**
 * Free resources allocated by oe_get_revocation_info() and
 * oe_get_revocation_info_from_certs().
 *
 * @param args[in] the revocation info.
 */
void oe_free_get_revocation_info_args(oe_get_revocation_info_args_t* args);

OE_EXTERNC_END

#endif // _OE_COMMON_REVOCATION_H
