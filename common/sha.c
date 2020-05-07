// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/raise.h>

oe_result_t oe_sha256(const void* data, size_t size, OE_SHA256* sha256)
{
    oe_result_t result = OE_FAILURE;
    oe_sha256_context_t ctx = {0};
    OE_CHECK(oe_sha256_init(&ctx));
    OE_CHECK(oe_sha256_update(&ctx, data, size));
    OE_CHECK(oe_sha256_final(&ctx, sha256));
    result = OE_OK;
done:
    return result;
}
