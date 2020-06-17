// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_PLUGIN
#define _OE_INTERNAL_SGX_PLUGIN

#include <openenclave/bits/report.h>

OE_EXTERNC_BEGIN

/**
 * The SGX plugin UUID.
 */
#define OE_SGX_PLUGIN_UUID                                                \
    {                                                                     \
        0xa3, 0xa2, 0x1e, 0x87, 0x1b, 0x4d, 0x40, 0x14, 0xb7, 0x0a, 0xa1, \
            0x25, 0xd2, 0xfb, 0xcd, 0x8c                                  \
    }

#define OE_FORMAT_UUID_SGX_ECDSA_P256 OE_SGX_PLUGIN_UUID

#define OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION                              \
    {                                                                     \
        0x09, 0x26, 0x8c, 0x33, 0x6e, 0x0b, 0x45, 0xe5, 0x8a, 0x27, 0x15, \
            0x64, 0x4d, 0x0e, 0xf8, 0x9a                                  \
    }

#define OE_FORMAT_UUID_SGX_EPID_LINKABLE                                  \
    {                                                                     \
        0xf2, 0x28, 0xaa, 0x3f, 0xde, 0x4d, 0x49, 0xd3, 0x88, 0x4c, 0xb2, \
            0xaa, 0x87, 0xa5, 0x0d, 0xa6                                  \
    }

#define OE_FORMAT_UUID_SGX_EPID_UNLINKABLE                                \
    {                                                                     \
        0x5c, 0x35, 0xd2, 0x90, 0xa2, 0xc2, 0x4c, 0x55, 0x9e, 0x13, 0x5a, \
            0xd7, 0x32, 0x74, 0x6c, 0x88                                  \
    }

#define OE_SGX_PLUGIN_CLAIMS_VERSION 1

/**
 *  Serialized header for the custom claims.
 */
typedef struct _oe_sgx_plugin_claims_header
{
    uint64_t version;
    uint64_t num_claims;
} oe_sgx_plugin_claims_header_t;

/**
 * Serialzied entry for custom claims. Each entry will have the name and value
 * sizes and then the contents of the name and value respectively.
 */
typedef struct _oe_sgx_plugin_claims_entry
{
    uint64_t name_size;
    uint64_t value_size;
    uint8_t name[];
    // name_size bytes follow.
    // value_size_bytes follow.
} oe_sgx_plugin_claims_entry_t;

/**
 * oe_sgx_serialize_claims
 *
 * Serializes a list of claims.
 *
 * This is available in the enclave only.
 *
 * @experimental
 *
 * @param [in] custom_claims Custom claims to serialize.
 * @param [in] custom_claims_length Length of custom_claims.
 * @param [out] claims_out Pointer to the address of a dynamically
 * allocated buffer holding the serialized custom claims.
 * @param [out] claims_size_out Size of the serialized custom claims.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval An appropriate error code on failure.
 */
struct _OE_SHA256;
oe_result_t oe_sgx_serialize_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** claims_out,
    size_t* claims_size_out,
    struct _OE_SHA256* hash_out);

/**
 * oe_sgx_extract_claims
 *
 * Extract claims from an evidence buffer.
 *
 * This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] format_id Pointer to the evidence format ID requested.
 * @param[in] evidence Pointer to the evidence buffer.
 * @param[in] evidence_size Size of the evidence buffer.
 * @param[in] sgx_endorsements Pointer to the endorsements buffer.
 * @param[out] claims_out Pointer to the address of a dynamically allocated
 * buffer holding the list of claims (including base and custom claims).
 * @param[out] claims_length_out The length of the claims_out list.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval An appropriate error code on failure.
 */
struct _oe_sgx_endorsements_t;
oe_result_t oe_sgx_extract_claims(
    const oe_uuid_t* format_id,
    const uint8_t* evidence,
    size_t evidence_size,
    const struct _oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t** claims_out,
    size_t* claims_length_out);

OE_EXTERNC_END

#endif // _OE_INTENRAL_SGX_PLUGIN
