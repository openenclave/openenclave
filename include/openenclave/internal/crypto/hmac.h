// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HMAC_H
#define _OE_HMAC_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/crypto/sha.h>

OE_EXTERNC_BEGIN

/* Opaque representation of a HMAC-SHA256 context. */
typedef struct _oe_hmac_sha256_context
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_hmac_sha256_context_t;

/**
 * Initializes a context for computing a HMAC-SHA256
 *
 * @param context The handle of context to be initialized
 * @param key The key used to calculate the HMAC
 * @param keysize The size of the HMAC key
 *
 * @return OE_OK upon success
 */
oe_result_t oe_hmac_sha256_init(
    oe_hmac_sha256_context_t* context,
    const uint8_t* key,
    size_t keysize);

/**
 * Extends a HMAC-SHA256 hash to include additional data
 *
 * This function extends the HMAC-SHA256 hash context with additional data.
 * This function may be called multiple times for the given context.
 *
 * @param context handle of context to extended
 * @param data buffer of data to be hashed
 * @param size size of the buffer
 *
 * @return OE_OK upon success
 */
oe_result_t oe_hmac_sha256_update(
    oe_hmac_sha256_context_t* context,
    const void* data,
    size_t size);

/**
 * Computes the final HMAC-SHA256 hash
 *
 * This function computes the final HMAC-SHA256 hash and writes it to the user
 * buffer.
 *
 * @param context handle of context to finalized
 * @param sha256 buffer where hash is written
 *
 * @return OE_OK upon success
 */
oe_result_t oe_hmac_sha256_final(
    oe_hmac_sha256_context_t* context,
    OE_SHA256* sha256);

/**
 * Deletes and frees the the given HMAC-SHA256 context
 *
 * @param context handle of context to be freed
 *
 * @return OE_OK upon success
 */
oe_result_t oe_hmac_sha256_free(oe_hmac_sha256_context_t* context);

OE_EXTERNC_END

#endif /* _OE_HMAC_H */
