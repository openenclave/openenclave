// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_MAGIC_H
#define _OE_HOST_CRYPTO_MAGIC_H

/* oe_crypto magic numbers for host types are shared
 * between OpenSSL and BCrypt implementations */

#define OE_CERT_MAGIC 0xbc8e184285de4d2a
#define OE_CERT_CHAIN_MAGIC 0xa5ddf70fb28f4480
#define OE_CRL_MAGIC 0xe8c993b1cca24906

#define OE_EC_PRIVATE_KEY_MAGIC 0x19a751419ae04bbc
#define OE_EC_PUBLIC_KEY_MAGIC 0xb1d39580c1f14c02
#define OE_RSA_PRIVATE_KEY_MAGIC 0x7bf635929a714b2c
#define OE_RSA_PUBLIC_KEY_MAGIC 0x8f8f72170025426d

#endif /* _OE_HOST_CRYPTO_MAGIC_H */
