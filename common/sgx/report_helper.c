// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/report.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/utils.h>
#include "../common.h"

oe_result_t oe_sgx_get_signer_id_from_public_key(
    const char* pem,
    size_t pem_size,
    uint8_t* signer_id,
    size_t* signer_id_size)
{
    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus. This value
    // is populated by the signer_id sub-field of a parsed oe_report_t's
    // identity field.

    oe_result_t result = OE_FAILURE;
    oe_rsa_public_key_t key = {0};
    bool key_initialized = false;

    if (!pem || !pem_size || !signer_id_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (*signer_id_size < OE_SIGNER_ID_SIZE)
    {
        *signer_id_size = OE_SIGNER_ID_SIZE;
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    if (!signer_id)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_rsa_public_key_read_pem(&key, (uint8_t*)pem, pem_size));
    key_initialized = true;

    {
        uint8_t modulus[OE_KEY_SIZE] = {0};
        size_t modulus_size = sizeof(modulus);
        OE_CHECK(oe_rsa_public_key_get_modulus(&key, modulus, &modulus_size));

        // RSA key length is the modulus length, so these have to be equal.
        if (modulus_size != OE_KEY_SIZE)
            OE_RAISE(OE_FAILURE);

        oe_mem_reverse_inplace(modulus, sizeof(modulus));

        OE_SHA256 sha256 = {0};
        OE_CHECK(oe_sha256(modulus, sizeof(modulus), &sha256));

        OE_STATIC_ASSERT(OE_SIGNER_ID_SIZE == sizeof(sha256.buf));
        memcpy(signer_id, sha256.buf, OE_SIGNER_ID_SIZE);
    }

    *signer_id_size = OE_SIGNER_ID_SIZE;
    result = OE_OK;

done:
    if (key_initialized)
        oe_rsa_public_key_free(&key);
    return result;
}
