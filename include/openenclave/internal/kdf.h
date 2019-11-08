// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_KDF_INTERNAL_H
#define _OE_KDF_INTERNAL_H

#include "crypto/kdf.h"

OE_EXTERNC_BEGIN

/**
 * Creates the fixed data as specified by NIST SP800-108.
 * Specfically, it produces the byte array in the form of
 * Label || 0x00 || Context || OutputKeySizeInBits.
 *
 * @param label The label data
 * @param label_size The length of the label
 * @param context The context data
 * @param context_size The length of the context
 * @param output_key_size The size of the desired derived key in bytes
 * @param fixed_data The pointer to an output buffer where the fixed data
 * will be written to
 * @param fixed_data_size The size of the output fixed data buffer
 *
 * @return OE_OK upon success
 * @return OE_CONSTRAINT_FAILED if derived key size is too large
 * @return OE_FAILURE if there is generic failure
 * @return OE_INVALID_PARAMETER if there is an invalid parameter
 * @return OE_OUT_OF_MEMORY if there is no memory available
 */
oe_result_t oe_kdf_create_fixed_data(
    const uint8_t* label,
    size_t label_size,
    const uint8_t* context,
    size_t context_size,
    size_t output_key_size,
    uint8_t** fixed_data,
    size_t* fixed_data_size);

OE_EXTERNC_END

#endif /* _OE_KDF_INTERNAL_H */
