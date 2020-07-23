// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file eeid.h
 *
 * This file declares internal EEID structures and functions.
 *
 */

#ifndef _OE_INTERNAL_EEID_H
#define _OE_INTERNAL_EEID_H

#ifdef OE_WITH_EXPERIMENTAL_EEID

#include <openenclave/bits/eeid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/sha.h>

/** This is the public key corresponding to the private key OE_DEBUG_SIGN_KEY in
 * signkey.c/.h. */
static const uint8_t OE_DEBUG_PUBLIC_KEY[] = {
    0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a, 0xa2, 0x88, 0x90,
    0xce, 0x73, 0xe4, 0x33, 0x63, 0x83, 0x77, 0xf1, 0x79, 0xab, 0x44,
    0x56, 0xb2, 0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

/**
 * Determine whether memory size settings are those of a base image to be used
 * with EEID.
 *
 * @param[in] sizes The memory size settings of an SGX enclave.
 *
 * @returns Returns true if **sizes** are consistent with those of an EEID base
 * image.
 *
 */
int is_eeid_base_image(const oe_enclave_size_settings_t* sizes);

/**
 * Serialize an oe_eeid_t.
 *
 * This function serializes an oe_eeid_t into a byte buffer.
 *
 * @param[in] eeid The oe_eeid_t to serialize.
 *
 * @param[in] data The EEID data (config) to serialize.
 *
 * @param[in] data_size The size of **data**.
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
    const uint8_t* data,
    size_t data_size,
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
 * @param[out] data The EEID data.
 *
 * @param[out] data_size The size of **data**.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_deserialize_eeid(
    const char* buf,
    size_t buf_size,
    oe_eeid_t* eeid,
    uint8_t** data,
    size_t* data_size);

/**
 * Remeasure EEID-defined memory pages.
 *
 * This function remeasures the additional memory pages added during
 * EEID-enabled enclave creation.
 *
 * @param[in] eeid The EEID containing the required size settings.
 *
 * @param[in] config_hash The SHA256 of the enclave config.
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
    OE_SHA256* computed_enclave_hash,
    bool with_eeid_pages,
    bool static_sizes);

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
 * @param[in] reported_sgx_attributes Attributes reported in the SGX report.
 *
 * @param[in] reported_misc_select Reported miscselect field of SGX report.
 *
 * @param[in] eeid The oe_eeid_t holding all relevant information about the base
 * image.
 *
 * @param[in] config_hash The SHA256 of the enclave config.
 *
 * @param[out] base_enclave_hash The hash of the base image
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
    const sgx_attributes_t* reported_sgx_attributes,
    uint32_t reported_misc_select,
    const uint8_t** base_enclave_hash,
    const oe_eeid_t* eeid,
    const oe_enclave_size_settings_t* base_image_sizes);

/**
 * Create an oe_eeid_t for SGX.
 *
 * @param[in] data The EEID data
 *
 * @param[in] data_size The size of **data**.
 *
 * @param[out] eeid The oe_eeid_t.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_create_eeid_sgx(oe_eeid_t** eeid);

/**
 * Compute the required size in bytes of an oe_eeid_t
 *
 * @param[in] eeid The oe_eeid_t
 *
 * @returns Returns OE_OK on success.
 *
 */
size_t oe_eeid_byte_size(const oe_eeid_t* eeid);

/**
 * Convert an oe_eeid_t into a buffer using network byte-order.
 *
 * @param[in] eeid The oe_eeid_t to convert.
 *
 * @param[in] buffer The buffer to write to.
 *
 * @param[in] buffer_size Size of **buffer**.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_eeid_hton(
    const oe_eeid_t* eeid,
    uint8_t* buffer,
    size_t buffer_size);

/**
 * Read an oe_eeid_t from a buffer using host byte-order.
 *
 * @param[in] buffer The buffer to write to.
 *
 * @param[in] buffer_size Size of **buffer**.
 *
 * @param[in] eeid The oe_eeid_t to convert to.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_eeid_ntoh(
    const uint8_t* buffer,
    size_t buffer_size,
    oe_eeid_t* eeid);

typedef struct
{
    size_t sgx_evidence_size;     /* Size of base-image evidence */
    size_t sgx_endorsements_size; /* Size of base-image endorsements */
    size_t eeid_size;             /* Size of EEID */
    uint8_t data[];               /* Data (same order as the sizes) */
} oe_eeid_evidence_t;

/**
 * Serialize a uint64_t in network byte-order into a buffer.
 *
 * @param[in] x The uint64_t to serialize.
 *
 * @param[inout] position The position in a buffer to write to (will be
 * updated).
 *
 * @param[inout] remaining The remaining space in the buffer (will be updated).
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t hton_uint64_t(uint64_t x, uint8_t** position, size_t* remaining);

/**
 * Deserialize a uint64_t from network byte-order into a buffer.
 *
 * @param[inout] position The position in a buffer to read from (will be
 * updated).
 *
 * @param[inout] remaining The remaining space in the buffer (will be updated).
 *
 * @param[out] x The uint64_t to deserialize.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t ntoh_uint64_t(
    const uint8_t** position,
    size_t* remaining,
    uint64_t* x);

/**
 * Serialize a oe_enclave_size_settings_t in network byte-order into a buffer.
 *
 * @param[in] sizes The oe_enclave_size_settings_t to serialize.
 *
 * @param[inout] position The position in a buffer to write to (will be
 * updated).
 *
 * @param[inout] remaining The remaining space in the buffer (will be updated).
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_enclave_size_settings_hton(
    const oe_enclave_size_settings_t* sizes,
    uint8_t** position,
    size_t* remaining);

/**
 * Deserialize a oe_enclave_size_settings_t from network byte-order into a
 * buffer.
 *
 * @param[inout] position The position in a buffer to write to (will be
 * updated).
 *
 * @param[inout] remaining The remaining space in the buffer (will be updated).
 *
 * @param[out] sizes The oe_enclave_size_settings_t to deserialize.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_enclave_size_settings_ntoh(
    const uint8_t** position,
    size_t* remaining,
    oe_enclave_size_settings_t* sizes);

/**
 * Convert an oe_eeid_evidence_t into a buffer using network byte-order.
 *
 * @param[in] evidence The oe_eeid_evidence_t to convert.
 *
 * @param[in] buffer The buffer to write to.
 *
 * @param[in] buffer_size Size of **buffer**.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_eeid_evidence_hton(
    const oe_eeid_evidence_t* evidence,
    uint8_t* buffer,
    size_t buffer_size);

/**
 * Read an oe_eeid_evidence_t from a buffer using host byte-order.
 *
 * @param[in] buffer The buffer to read from
 *
 * @param[in] buffer_size Size of **buffer**.
 *
 * @param[in] evidence The oe_eeid_evidence_t to convert to.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_eeid_evidence_ntoh(
    const uint8_t* buffer,
    size_t buffer_size,
    oe_eeid_evidence_t* evidence);

/**
 * This struct defines a buffer for enclave configuration with EEID.
 */
typedef struct
{
    uint8_t* data;
    size_t size;
} oe_enclave_initialization_data_t;

/**
 * This struct defines an enclave with EEID data.
 */
typedef struct
{
    oe_enclave_t* enclave;
    oe_enclave_initialization_data_t config;
} oe_enclave_with_config_t;

#endif /* OE_WITH_EXPERIMENTAL_EEID */

#endif /* _OE_INTERNAL_EEID_H */