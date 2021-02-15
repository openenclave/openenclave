// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file host_verify.h
 *
 * This file defines the programming interface verifying reports for remote
 * attestation.
 *
 */
#ifndef _OE_HOST_VERIFY_H
#define _OE_HOST_VERIFY_H

#ifdef _OE_ENCLAVE_H
#error "enclave.h must not be in the same compilation unit as host_verify.h"
#endif

#include "bits/defs.h"
#include "bits/evidence.h"
#include "bits/report.h"
#include "bits/result.h"

OE_EXTERNC_BEGIN

/**
 * Verify the integrity of the remote report and its signature.
 *
 * This function verifies that the report signature is valid. It
 * verifies that the signing authority is rooted to a trusted authority
 * such as the enclave platform manufacturer.
 *
 * @param report The buffer containing the report to verify.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report Optional **oe_report_t** structure to populate
 * with the report properties in a standard format.
 * @param[out] endorsements An optional output pointer that will be assigned
 * the address of the endorsements buffer.
 * @param[out] endorsements_size A pointer that points to the size of
 * the endorsements buffer in bytes.
 *
 * @retval OE_OK The report was successfully verified.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_remote_report(
    const uint8_t* report,
    size_t report_size,
    const uint8_t* endorsement,
    size_t endorsement_size,
    oe_report_t* parsed_report);

/**
 * identity validation callback type
 * @param[in] identity a pointer to an enclave's identity information
 * @param[in] arg caller defined context
 */
typedef oe_result_t (
    *oe_identity_verify_callback_t)(oe_identity_t* identity, void* arg);

/**
 * oe_verify_attestation_certificate
 *
 * This function perform a custom validation on the input certificate. This
 * validation includes extracting an attestation evidence extension from the
 * certificate before validating this evidence. An optional
 * enclave_identity_callback could be passed in for a calling client to further
 * validate the identity of the enclave creating the quote.
 * OE_FAILURE is returned if the expected certificate extension OID is not
 * found.
 * @param[in] cert_in_der a pointer to buffer holding certificate contents
 *  in DER format
 * @param[in] cert_in_der_len size of certificate buffer above
 * @param[in] enclave_identity_callback callback routine for custom identity
 * checking
 * @param[in] arg an optional context pointer argument specified by the caller
 * when setting callback
 * @retval OE_OK on a successful validation
 * @retval OE_VERIFY_FAILED on quote failure
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid
 * @retval OE_FAILURE general failure
 * @retval other appropriate error code
 */
oe_result_t oe_verify_attestation_certificate(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_identity_verify_callback_t enclave_identity_callback,
    void* arg);

OE_EXTERNC_END

#endif
