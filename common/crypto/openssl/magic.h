// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_CRYPTO_OPENSSL_MAGIC_H
#define _OE_COMMON_CRYPTO_OPENSSL_MAGIC_H

#if !defined(OE_BUILD_ENCLAVE)
/* oe_crypto magic numbers for host OpenSSL implementation */
#define OE_CERT_MAGIC 0xbc8e184285de4d2a
#define OE_CERT_CHAIN_MAGIC 0xa5ddf70fb28f4480
#define OE_CRL_MAGIC 0xe8c993b1cca24906
#define OE_EC_PRIVATE_KEY_MAGIC 0x19a751419ae04bbc
#define OE_EC_PUBLIC_KEY_MAGIC 0xb1d39580c1f14c02
#define OE_RSA_PRIVATE_KEY_MAGIC 0x7bf635929a714b2c
#define OE_RSA_PUBLIC_KEY_MAGIC 0x8f8f72170025426d
#else
/* oe_crypto magic numbers for enclave OpenSSL implementation */
#define OE_CERT_MAGIC 0xa7a55f4322919317
#define OE_CERT_CHAIN_MAGIC 0xa87e5d8e25671870
#define OE_CRL_MAGIC 0x8f062e782b5760b2
#define OE_EC_PRIVATE_KEY_MAGIC 0x9ffae0517397b76c
#define OE_EC_PUBLIC_KEY_MAGIC 0xb8e1d57e9be31ed7
#define OE_RSA_PRIVATE_KEY_MAGIC 0xba24987b29769828
#define OE_RSA_PUBLIC_KEY_MAGIC 0x92f1fdf6c81b4aaa
#endif

#endif /* _OE_COMMON_CRYPTO_OPENSSL_MAGIC_H */
