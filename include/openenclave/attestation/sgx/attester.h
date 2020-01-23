// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file attester.h
 *
 * This file defines the API for getting the SGX attester.
 *
 */

#ifndef _OE_ATTESTATION_SGX_ATTESTER_H
#define _OE_ATTESTATION_SGX_ATTESTER_H

#ifdef _OE_HOST_H
#error "The sgx attester (sgx/attester.h) is only available for the enclave."
#endif

#include <openenclave/attestation/plugin.h>

OE_EXTERNC_BEGIN

/**
 *  The `opt_params` field for `oe_get_evidence` identical to the `opt_params`
 *  field `oe_get_report`. In other words, it is the output of
 * `oe_get_target_info` for local attestation and is ignored for remote
 *  attestation.
 */
typedef void* oe_sgx_plugin_opt_params;

/**
 * Helper function that returns the SGX attester that can then be sent to
 * `oe_register_attester`.
 *
 * @experimental
 *
 * @retval A pointer to the SGX attester. This function never fails.
 */
oe_attester_t* oe_sgx_plugin_attester(void);

/**
 * Helper function that serializes a list of claims.
 *
 * @experimental
 *
 * @param [in] custom_claims Claims to serialize.
 * @param [in] size_t custom_claims_length Length of **custom_claims**.
 * @param [out] uint8_t** claims_out Output claims.
 * @param [out] size_t* claims_size_out Length of **claims_out**.
 *
 * @retval OE_OK on success.
 */
struct _OE_SHA256;
oe_result_t oe_sgx_serialize_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** claims_out,
    size_t* claims_size_out,
    struct _OE_SHA256* hash_out);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */
