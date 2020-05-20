// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file verifier.h
 *
 * This file defines the API for getting the SGX verifier.
 *
 */

#ifndef _OE_ATTESTATION_SGX_VERIFIER_H
#define _OE_ATTESTATION_SGX_VERIFIER_H

#include <openenclave/attestation/plugin.h>

OE_EXTERNC_BEGIN

/**
 * Helper function that returns the SGX verifier that can then be sent to
 * `oe_register_verifier`.
 *
 * @experimental
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
oe_verifier_t* oe_sgx_plugin_verifier(void);

/**
 * Helper function that extracts claims from an evidence buffer.
 *
 * @experimental
 *
 * @param[in] evidence
 *
 * @param[in] evidence_size
 *
 * @param[in] sgx_endorsements
 *
 * @param[out] claims_out
 *
 * @param[out] claims_length_out
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
struct _oe_sgx_endorsements_t;
oe_result_t oe_sgx_extract_claims(
    const uint8_t* evidence,
    size_t evidence_size,
    const struct _oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t** claims_out,
    size_t* claims_length_out);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */
