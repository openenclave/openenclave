// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_BCRYPT_EC_H
#define _OE_HOST_CRYPTO_BCRYPT_EC_H

#include <openenclave/internal/ec.h>
#include "bcrypt.h"

/* Caller is responsible for validating parameters */
void oe_ec_public_key_init(
    oe_ec_public_key_t* public_key,
    BCRYPT_KEY_HANDLE* key_handle);

#endif /* _OE_HOST_CRYPTO_BCRYPT_EC_H */
