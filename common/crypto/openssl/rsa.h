// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_CRYPTO_OPENSSL_RSA_H
#define _OE_COMMON_CRYPTO_OPENSSL_RSA_H

#include <openenclave/internal/rsa.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/param_build.h>
#endif

/* Caller is responsible for validating parameters */
void oe_rsa_public_key_init(oe_rsa_public_key_t* public_key, EVP_PKEY* pkey);

#endif /* _OE_COMMON_CRYPTO_OPENSSL_RSA_H */
