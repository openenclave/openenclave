// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QUOTE_H
#define _OE_COMMON_QUOTE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/cert.h>

OE_EXTERNC_BEGIN

/*!
 * Verify quote with optional collaterals.
 *
 * @param[in] quote Input quote.
 * @param[in] quote_size The size of the quote.
 * @param[in] collaterals Optional collaterals related to a remote quote.
 * @param[in] collatterals_size The size of the collaterals.
 * @param[in] input_validation_time Optional time to use for validation,
 * defaults to the time the collaterals were created.
 */
oe_result_t oe_verify_quote_internal_with_collaterals(
    const uint8_t* quote,
    size_t quote_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* input_validation_time);

/*!
 * Retrieves certifate chain from the quote.
 *
 * Caller is responsible for deallocating memory in pck_cert_chain.
 *
 * @param[in] quote Input quote.
 * @param[in] quote_size The size of the quote.
 * @param[out] pem_pck_certifcate Pointer to the quote where the certificate PCK
 * starts.
 * @param[out] pem_pck_certificate_size Size of the PCK certificate.
 * @param[out] pck_cert_chain Reference to an instance of oe_cert_chain_t where
 * to store the chain.  Caller needs to free resources by calling
 * oe_cert_chain_free()
 */
oe_result_t oe_get_quote_cert_chain_internal(
    const uint8_t* quote,
    const size_t quote_size,
    const uint8_t** pem_pck_certificate,
    size_t* pem_pck_certificate_size,
    oe_cert_chain_t* pck_cert_chain);

/*!
 * Find the valid datetime range for the given quote, collaterals.  This
 * function accounts for the following items:
 *
 * 1. From the quote:
 *          a) Root CA.
 *          b) Intermediate CA.
 *          b) PCK CA.
 * 2. From the revocation info:
 *          a) Root CA CRL.
 *          b) Intermediate CA CRL.
 *          c) PCK CA CRL.
 *          d) TCB info cert.
 *          e) TCB info.
 * 3. From QE identity info
 *          a) QE identity cert.
 *          b) QE identity.
 *
 * @param[in] quote Input quote.
 * @param[in] quote_size The size of the quote.
 * @param[in] collaterals Collaterals related to the quote.
 * @param[in] collatterals_size The size of the collaterals.
 * @param[out] valid_from validity_from The date from which the quote is valid.
 * @param[out] valid_until validity_until The date which the quote expires.
 */
oe_result_t oe_get_quote_validity_with_collaterals_internal(
    const uint8_t* quote,
    const size_t quote_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* valid_from,
    oe_datetime_t* valid_until);

OE_EXTERNC_END

#endif // _OE_COMMON_QUOTE_H
