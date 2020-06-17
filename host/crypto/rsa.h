// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_RSA_H
#define _OE_HOST_CRYPTO_RSA_H

#include <openenclave/internal/rsa.h>

/* Caller is responsible for freeing public key. */
oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key);

#endif /* _OE_HOST_CRYPTO_RSA_H */
