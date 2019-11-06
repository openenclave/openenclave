// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_BCRYPT_RSA_H
#define _OE_HOST_CRYPTO_BCRYPT_RSA_H

#include <openenclave/internal/rsa.h>
#include "bcrypt.h"

/* Caller is responsible for validating parameters */
void oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    BCRYPT_KEY_HANDLE* key_handle);

#endif /* _OE_HOST_CRYPTO_BCRYPT_RSA_H */
