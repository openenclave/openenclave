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
 * Gets a list of evidence formats accepted by the verifier for evidence
 * verification.
 *
 * @experimental
 *
 * @param[out] formats An output pointer that will be assigned the address of
 * a dynamically allocated buffer that holds the returned list of formats
 * supported for evidence verification.
 * @param[out] formats_length A pointer that points to the length of the
 * returned formats list (number of format ID entries).
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_get_formats(
    oe_uuid_t** formats,
    size_t* formats_length);

/**
 * oe_verifier_free_formats
 *
 * Frees a formats list.
 *
 * @experimental
 *
 * @param[in] formats The formats list.
 * @retval OE_OK The function succeeded.
 * @retval other appropriate error code.
 */
oe_result_t oe_verifier_free_formats(oe_uuid_t* formats);

/**
 * oe_verifier_get_format_settings
 *
 * Gets the optional settings data for the input evidence format.
 *
 * @experimental
 *
 * @param[in] format The format for which to retrieve the optional settings.
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
    const oe_uuid_t* format,
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
 *     - Version number. Must be 1.
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
 *     - The format UUID of the verified evidence.
 *
 * @experimental
 *
 * @param[in] evidence_buffer The evidence buffer.
 * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
 * @param[in] endorsements_buffer The optional endorsements buffer.
 * @param[in] endorsements_buffer_size The size of endorsements_buffer in bytes.
 * @param[in] policies An optional list of policies to use.
 * @param[in] policies_size The size of the policy list.
 * @param[out] claims The list of claims (including base and custom).
 * @param[out] claims_length The length of the claims list.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_verify_evidence(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);

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
