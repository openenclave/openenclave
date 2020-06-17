// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <openenclave/internal/random.h>
#include "bcrypt.h"

oe_result_t oe_random_internal(void* data, size_t size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* For consistency with OpenSSL, keep this to int max */
    if (size > OE_INT_MAX)
        return OE_INVALID_PARAMETER;

    NTSTATUS status = BCryptGenRandom(
        NULL, data, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BcryptGenRandom failed (err=%#x)\n", status);

    result = OE_OK;

done:
    return result;
}
