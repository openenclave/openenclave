// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SHA_H
#define _OE_SHA_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_SHA256_SIZE 32

/* Opaque representation of a SHA-256 context */
typedef struct _oe_sha256_context
{
    /* Internal private implementation */
    uint64_t impl[16];
} oe_sha256_context_t;

typedef struct _OE_SHA256
{
    unsigned char buf[OE_SHA256_SIZE];
} OE_SHA256;

/**
 * Initializes a context for computing a SHA-256 hash
 *
 * This function initializes a context for computing a SHA-256 hash.
 *
 * @param context handle of context to be initialized
 *
 * @return OE_OK upon success
 */
oe_result_t oe_sha256_init(oe_sha256_context_t* context);

/**
 * Extends a SHA-256 hash to include additional data
 *
 * This function extends the given SHA-256 hash context with additional data.
 * This function may be called multiple times for the given context.
 *
 * @param context handle of context to extended
 * @param data buffer of data to be hashed
 * @param size size of the buffer
 *
 * @return OE_OK upon success
 */
oe_result_t oe_sha256_update(
    oe_sha256_context_t* context,
    const void* data,
    size_t size);

/**
 * Computes the final SHA-256 hash
 *
 * This function computes the final SHA-256 hash and writes it to the user
 * buffer.
 *
 * @param context handle of context to finalized
 * @param sha256 buffer where hash is written
 * @param size size of the buffer
 *
 * @return OE_OK upon success
 */
oe_result_t oe_sha256_final(oe_sha256_context_t* context, OE_SHA256* sha256);

/**
 * Computes the SHA-256 hash of the input data
 *
 * This is a convenience function that can be used if the full data is
 * available at once.
 *
 * @param[in] data buffer of data to be hashed
 * @param[in] size size of the buffer
 * @param[out] sha256 buffer where hash is written
 *
 * @return OE_OK upon success
 */
oe_result_t oe_sha256(const void* data, size_t size, OE_SHA256* sha256);

#ifdef OE_WITH_EXPERIMENTAL_EEID
/**
 * Saves the internal state of a SHA-256 context
 *
 * This function saves the internal state of a SHA-256 context to H and N
 * buffers.
 *
 * @param context handle of context to finalized
 * @param internal_hash buffer to write the internal hash to
 * @param num_hashed buffer to write the number of hashed bytes to
 *
 * @return OE_OK upon success
 */
oe_result_t oe_sha256_save(
    const oe_sha256_context_t* context,
    uint32_t* internal_hash,
    uint32_t* num_hashed);

/**
 * Restores the internal state of a SHA-256 context
 *
 * This function restores the internal state of a SHA-256 context from
 * H and N buffers.
 *
 * @param context handle of context to finalized
 * @param internal_hash buffer to read the internal hash from
 * @param num_hashed buffer to read the number of hashed bytes from
 *
 * @return OE_OK upon success
 */
oe_result_t oe_sha256_restore(
    oe_sha256_context_t* context,
    const uint32_t* internal_hash,
    const uint32_t* num_hashed);
#endif

OE_EXTERNC_END

#endif /* _OE_SHA_H */
