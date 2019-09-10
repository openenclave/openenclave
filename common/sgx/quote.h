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
 * @param quote[in] Input quote.
 * @param quote_size[in] The size of the quote.
 * @param collaterals[in] Optional collaterals related to the quote.
 * @param collatterals_size[in] The size of the collaterals.
 * @param input_validation_time[in] Optional time to use for validation,
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
 * @param quote[in] Input quote.
 * @param quote_size[in] The size of the quote.
 * @param pem_pck_certifcate[out] Pointer to the quote where the certificate PCK
 * starts.
 * @param pem_pck_certificate_size[out] Size of the PCK certificate.
 * @param pck_cert_chain[out] Reference to an instance of oe_cert_chain_t where
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
 * @param quote[in] Input quote.
 * @param quote_size[in] The size of the quote.
 * @param collaterals[in] Optional collaterals related to the quote.
 * @param collatterals_size[in] The size of the collaterals.
 * @param valid_from[out] validity_from The date from which the quote is valid.
 * @param valid_until[out] validity_until The date which the quote expires.
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
