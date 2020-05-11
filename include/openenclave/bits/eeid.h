// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file eeid.h
 *
 * This file defines the EEID structure.
 *
 */

#ifndef _OE_BITS_EEID_H
#define _OE_BITS_EEID_H

#include "properties.h"

OE_EXTERNC_BEGIN

#ifdef OE_WITH_EXPERIMENTAL_EEID

// This is the public key corresponding to the private key OE_DEBUG_SIGN_KEY in
// signkey.c/.h.
static const uint8_t OE_DEBUG_PUBLIC_KEY[] = {
    0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a, 0xa2, 0x88, 0x90,
    0xce, 0x73, 0xe4, 0x33, 0x63, 0x83, 0x77, 0xf1, 0x79, 0xab, 0x44,
    0x56, 0xb2, 0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

/*
**==============================================================================
**
** oe_eeid_t
**
**==============================================================================
*/
typedef struct oe_eeid_t_
{
    struct
    {
        uint32_t H[8];
        uint32_t N[2];
    } hash_state; /* internal state of the hash computation at the end of
                           the enclave base image */
    uint64_t signature_size; /* size of signature */
    uint8_t signature[1808]; /* base-image signature and associated data (for
                           SGX, the complete sigstruct of the base image) */
    oe_enclave_size_settings_t
        size_settings; /* heap, stack and thread configuration for this instance
                        */
    uint64_t vaddr; /* location of the added data pages in enclave memory; EEID
                       follows immediately thereafter */
    uint64_t entry_point; /* entry point of the image */
    uint64_t data_size;   /* size of application EEID */
    uint8_t data[];       /* actual application EEID */
} oe_eeid_t;

/**
 * Serialize an oe_eeid_t.
 *
 * This function serializes an oe_eeid_t into a byte buffer.
 *
 * @param[in] eeid The oe_eeid_t to serialize.
 *
 * @param[in] buf The buffer to serialize to (must be non-NULL).
 *
 * @param[in] buf_size The size of **buf**.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_serialize_eeid(
    const oe_eeid_t* eeid,
    char* buf,
    size_t buf_size);

/**
 * Deserialize an oe_eeid_t.
 *
 * This function deserializes an oe_eeid_t from a byte buffer.
 *
 * @param[in] buf The buffer to serialize to.
 *
 * @param[in] buf_size The size of **buf**.
 *
 * @param[out] eeid The oe_eeid_t to deserialize to (must be non-NULL).
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_deserialize_eeid(
    const char* buf,
    size_t buf_size,
    oe_eeid_t* eeid);

struct _OE_SHA256;

#define OE_EEID_MAGIC                                                        \
    0xEE1DEE1DEE1DEE1D /* magic value to recognize EEID pages in the enclave \
                         without having to patch any image symbols.*/

/**
 * Remeasure EEID-defined memory pages.
 *
 * This function remeasures the additional memory pages added during
 * EEID-enabled enclave creation.
 *
 * @param[in] eeid The EEID containing the required size settings.
 *
 * @param[in] computed_enclave_hash The final enclave hash after the memory
 * pages have been added.
 *
 * @param[in] with_eeid_pages Flag indicating whether EEID pages should be
 * included (base image verification requires this to be disabled).
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_remeasure_memory_pages(
    const oe_eeid_t* eeid,
    struct _OE_SHA256* computed_enclave_hash,
    bool with_eeid_pages);

/**
 * Verify EEID hashes and signature.
 *
 * This function verifies the consistency of enclave hashes of base and extended
 * images, as well as the base image signature.
 *
 * @param[in] reported_enclave_hash Enclave hash of the extended image (as
 * reported in the oe_report_t).
 *
 * @param[in] reported_enclave_signer Enclave signer of the extended image (as
 * reported in the oe_report_t).
 *
 * @param[in] reported_product_id Product ID of the extended image (as reported
 * in the oe_report_t).
 *
 * @param[in] reported_security_version Security version of the extended image
 * (as reported in the oe_report_t).
 *
 * @param[in] reported_attributes Attributes of the extended image (as reported
 * in the oe_report_t).
 *
 * @param[in] eeid The oe_eeid_t holding all relevant information about the base
 * image.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t verify_eeid(
    const uint8_t* reported_enclave_hash,
    const uint8_t* reported_enclave_signer,
    uint16_t reported_product_id,
    uint32_t reported_security_version,
    uint64_t reported_attributes,
    const oe_eeid_t* eeid);

#endif /* OE_WITH_EXPERIMENTAL_EEID */

OE_EXTERNC_END

#endif /* _OE_BITS_EEID_H */
