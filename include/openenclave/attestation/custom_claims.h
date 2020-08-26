// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file custom_claims.h
 *
 * This file defines the programming interface for application software
 * to access the OE SDK attestation custom claims functionality.
 *
 */

#ifndef _OE_CUSTOM_CLAIMS
#define _OE_CUSTOM_CLAIMS

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN
#define OE_CUSTOM_CLAIMS_VERSION 1

/**
 * oe_free_serialized_custom_claims
 *
 * Free buffer of serialized custom claims.
 *
 * @param[in] custom_claims_buffer Serialized custom claims
 * buffer to free.
 * @retval OE_OK The function was successful.
 */
oe_result_t oe_free_serialized_custom_claims(uint8_t* custom_claims_buffer);

/**
 * oe_free_custom_claims
 *
 * Free list of custom claims.
 *
 * @param[in] custom_claims Custom claims array to free.
 * @param[in] custom_claims_length Length of custom_claims.
 * @retval OE_OK The function was successful.
 */
oe_result_t oe_free_custom_claims(
    oe_claim_t* custom_claims,
    size_t custom_claims_length);

/**
 * oe_serialize_custom_claims
 *
 * Serializes a list of custom claims.
 *
 * @param[in] custom_claims Custom claims to serialize.
 * @param[in] custom_claims_length Length of custom_claims.
 * @param[out] claims_out Pointer to the address of a dynamically
 * allocated buffer holding the serialized custom claims.
 * @param[out] claims_size_out Size of the serialized custom claims.
 * @retval OE_OK The function was successful.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
oe_result_t oe_serialize_custom_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** claims_out,
    size_t* claims_size_out);

/**
 * oe_deserialize_custom_claims
 *
 * Deserialize custom claim buffer
 *
 * @param[in] claims_buffer Pointer to the serialized custom claims buffer.
 * @param[in] claims_buffer_size Size of the serialized custom claims buffer
 * buffer.
 * @param[out] claims_out Pointer to the address of a dynamically allocated
 * buffer holding the list of custom claims.
 * @param[out] claims_length_out The length of the claims_out list.
 * @retval OE_OK The function was successful.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_CONSTRAINT_FAILED The serialized custom claims buffer size is too
 * small or invalid.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 * @retval OE_UNEXPECTED An unexpected error happened.
 */
oe_result_t oe_deserialize_custom_claims(
    const uint8_t* claims_buffer,
    size_t claims_buffer_size,
    oe_claim_t** claims_out,
    size_t* claims_length_out);
OE_EXTERNC_END

#endif //_OE_CUSTOM_CLAIMS
