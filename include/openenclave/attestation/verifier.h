// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file verifier.h
 *
 * This file defines the programming interface for application software
 * to access OE SDK verifier functionality for evidence verification.
 *
 */

#ifndef _OE_ATTESTATION_VERIFIER_H
#define _OE_ATTESTATION_VERIFIER_H

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * oe_verifier_initialize
 *
 * Initializes the verifier environment configured for the platform and
 * the calling application.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_initialize(void);

/**
 * oe_verifier_get_formats
 *
 * Gets a list of evidence format ids accepted by the verifier for evidence
 * verification.
 *
 * @experimental
 *
 * @param[out] format_ids An output pointer that will be assigned the address of
 * a dynamically allocated buffer that holds the returned list of format ids
 * supported for evidence verification.
 * @param[out] format_ids_length A pointer that points to the length of the
 * returned format id list (number of format id entries).
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_get_formats(
    oe_uuid_t** format_ids,
    size_t* format_ids_length);

/**
 * oe_verifier_free_formats
 *
 * Frees a formats list.
 *
 * @experimental
 *
 * @param[in] format_ids The formats list.
 * @retval OE_OK The function succeeded.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_free_formats(oe_uuid_t* format_ids);

/**
 * oe_verifier_get_format_settings
 *
 * Gets the optional settings data for the input evidence format.
 *
 * @experimental
 *
 * @param[in] format_id The format ID for which to retrieve the optional
 * settings.
 * @param[out] settings An output pointer that will be assigned the address of
 * a dynamically allocated buffer that holds the returned settings data. This
 * pointer will be assigned a NULL value if there is no settings needed.
 * @param[out] settings_size A pointer that points to the size of the returned
 * format settings buffer (number of bytes).
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_get_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** settings,
    size_t* settings_size);

/**
 * oe_verifier_free_format_settings
 *
 * Frees a format settings buffer.
 *
 * @experimental
 *
 * @param[in] settings The format settings buffer.
 * @retval OE_OK The function succeeded.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_free_format_settings(uint8_t* settings);

/**
 * oe_verify_evidence
 *
 * Verifies the attestation evidence and returns well known and custom claims.
 * This is available in the enclave and host.
 *
 * The following base claims will be returned at the minimum:
 *
 * - id_version (uint32_t)
 *     - Version number.
 * - security_version (uint32_t)
 *     - Security version of the enclave. (ISVN for SGX).
 * - attributes (uint64_t)
 *     - Attributes flags for the evidence:
 *         - OE_EVIDENCE_ATTRIBUTES_SGX_DEBUG: The evidence is for a debug mode
 *           SGX enclave.
 *         - OE_EVIDENCE_ATTRIBUTES_SGX_REMOTE: The evidence can be used for
 *           remote attestation of an SGX enclave.
 * - unique_id (uint8_t[32])
 *     - The unique ID for the enclave (MRENCLAVE for SGX).
 * - signer_id (uint8_t[32])
 *     - The signer ID for the enclave (MRSIGNER for SGX).
 * - product_id (uint8_t[32])
 *     - The product ID for the enclave (ISVPRODID for SGX).
 * - validity_from (oe_datetime_t, optional)
 *     - Overall datetime from which the evidence and endorsements are valid.
 * - validity_until (oe_datetime_t, optional)
 *     - Overall datetime at which the evidence and endorsements expire.
 * - format_uuid (uint8_t[16])
 *     - The format id of the verified evidence.
 *
 * @experimental
 *
 * @param[in] format_id The optional format id of the evidence to be verified.
 * If this parameter is NULL, the evidence_buffer (and endorsement_buffer if
 * not NULL) must contain data with an attestation header holding a valid
 * format id. Otherwise, this parameter must hold a valid format id, and the
 * envidence and endorsements data must not be wrapped with an attestation
 * header.
 * @param[in] evidence_buffer The evidence buffer.
 * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
 * @param[in] endorsements_buffer The optional endorsements buffer.
 * @param[in] endorsements_buffer_size The size of endorsements_buffer in bytes.
 * @param[in] policies An optional list of policies to use.
 * @param[in] policies_size The size of the policy list.
 * @param[out] claims If not NULL, an output pointer that will be assigned the
 * address of the dynamically allocated list of claims (including base and
 * custom).
 * @param[out] claims_length If not NULL, the length of the claims list.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_verify_evidence(
    const oe_uuid_t* format_id,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);

/**
 * Type definition for a claims verification callback.
 *
 * @param[in] claims a pointer to an array of claims
 * @param[in] claims_length length of the claims array
 * @param[in] arg caller defined context
 */
typedef oe_result_t (*oe_verify_claims_callback_t)(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg);

/**
 * oe_verify_attestation_certificate_with_evidence
 *
 * This function performs a custom validation on the input certificate. This
 * validation includes extracting an attestation evidence extension from the
 * certificate before validating this evidence. An optional
 * claim_verify_callback could be passed in for a calling client to further
 * validate the claims of the enclave creating the certificate.
 * OE_FAILURE is returned if the expected certificate extension OID is not
 * found.
 * @param[in] cert_in_der a pointer to buffer holding certificate contents
 *  in DER format
 * @param[in] cert_in_der_len size of certificate buffer above
 * @param[in] claim_verify_callback callback routine for custom claim checking
 * @param[in] arg an optional context pointer argument specified by the caller
 * when setting callback
 * @retval OE_OK on a successful validation
 * @retval OE_VERIFY_FAILED on quote failure
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid
 * @retval OE_FAILURE general failure
 * @retval other appropriate error code
 */
oe_result_t oe_verify_attestation_certificate_with_evidence(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_verify_claims_callback_t claim_verify_callback,
    void* arg);

/**
 * oe_free_claims
 *
 * Frees a claims list.
 *
 * @experimental
 *
 * @param[in] claims The list of claims.
 * @param[in] claims_length The length of the claims list.
 * @retval OE_OK The function succeeded.
 * @retval other appropriate error code.
 */
oe_result_t oe_free_claims(oe_claim_t* claims, size_t claims_length);

/**
 * oe_verifier_shutdown
 *
 * Shuts down the verifier environment configured for the platform and
 * the calling application.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_shutdown(void);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_VERIFIER_H */
