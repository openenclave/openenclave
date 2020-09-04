# Configuration Parity Analysis between MbedTLS and OpenSSL Crypto Libraries

This document compares the build-time configuration of MbedTLS, which
has been extenstively reviewed when the library was ported to OE,
against that of OpenSSL, which OE recently starts to support. The goal of this
analysis is to ensure the parity between the two. For certain configurations
that cannot achieve parity, the analysis also tries to reason out the gap.

*Note:* The following table only lists the options that are revelant to
the cryptographic algorithms. The table uses *CONFIG* or *!CONFIG* to indicate the
corresponding configuration is set or not.

## Parity analysis based on MbedlTLS

MbedTLS option | OE configuration | Equivalent OpenSSL option | Parity | Comment
:---|:---|:---|:---|:---|
MBEDTLS_CIPHER_MODE_CBC | Enabled | N/A | Yes | OpenSSL supports CBC mode by default. |
MBEDTLS_CIPHER_MODE_CFB | Disabled (by OE as unsafe block cipher mode) | N/A | No | OpenSSL always supports CFB mode and cannot be disabled by OE. |
MBEDTLS_CIPHER_MODE_CTR | Enabled | N/A | Yes | OpenSSL supports CTR mode by default. |
MBEDTLS_CIPHER_MODE_OFB | Enabled | N/A | Yes | OpenSSL supports OFB mode by default. |
MBEDTLS_CIPHER_MODE_XTS | Enabled | N/A | Yes | OpenSSL supports XTS mode by default. |
MBEDTLS_CIPHER_NULL_CIPHER | Disabled | N/A | No | OpenSSL does not have equivalent option. Mbed disables this option along with !MBEDTLS_ENABLE_WEAK_CIPHERSUITES. |
MBEDTLS_ENABLE_WEAK_CIPHERSUITES | Disabled | OPENSSL_NO_WEAK_SSL_CIPHERS | Partial | OE keeps the default configuration of OpenSSL that enables MBEDTLS_ENABLE_WEAK_CIPHERSUITES. Require further investigation to check the difference of weak ciphersuites in both implementation. |
MBEDTLS_CIPHER_PADDING_PKCS7 | Enabled (MbedTLS default) | N/A | Yes | OpenSSL supports padding by default. |
MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS | Enabled (MbedTLS default) | N/A | Yes | OpenSSL supports padding by default. |
MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN | Enabled (MbedTLS default) | N/A | Yes | OpenSSL supports padding by default. |
MBEDTLS_CIPHER_PADDING_ZEROS | Enabled (MbedTLS default) | N/A | Yes | OpenSSL supports padding by default. |
MBEDTLS_REMOVE_ARC4_CIPHERSUITES | Enabled | OPENSSL_NO_WEAK_SSL_CIPHERS | Yes | OE prevents the use of RC4 on OpenSSL by enabling the OPENSSL_NO_WEAK_SSL_CIPHERS option. |
MBEDTLS_REMOVE_3DES_CIPHERSUITES | Enabled | OPENSSL_NO_WEAK_SSL_CIPHERS | Yes | OE prevents the use of 3DES on OpenSSL by enabling the OPENSSL_NO_WEAK_SSL_CIPHERS option. |
MBEDTLS_ECP_DP_SECP192R1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_SECP224R1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_SECP256R1_ENABLED | Enabled (p256 matches NSA's suite B) | N/A | Yes | OpenSSL supports SECP 256r1 (i.e., X9.62 prime256v1) by default. |
MBEDTLS_ECP_DP_SECP384R1_ENABLED | Enabled (p384 matches NSA's suite B) | N/A | Yes | OpenSSL supports SECP 384r1 by default. |
MBEDTLS_ECP_DP_SECP521R1_ENABLED | Enabled (p521 matches NSA's suite B) | N/A | Yes | OpenSSL supports SPEC 521r1 by default. |
MBEDTLS_ECP_DP_SECP192K1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_SECP224K1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_SECP256K1_ENABLED | Enabled (p256k1 is used by bitcoin) | N/A | Yes | OpenSSL supports SECP256k1 by default. |
MBEDTLS_ECP_DP_BP256R1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_BP384R1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_BP512R1_ENABLED | Disabled (OE's choice to remove uncommon elliptic curves) | N/A | No | OpenSSL always enables all the supported curves. Cannot be disabled by OE. |
MBEDTLS_ECP_DP_CURVE25519_ENABLED | Enabled | N/A | Yes | OpenSSL supports curve 25519 by default. |
MBEDTLS_ECP_DP_CURVE448_ENABLED | Enabled | N/A | Yes | OpenSSL supports curve 448 by default. |
MBEDTLS_ECDSA_DETERMINISTIC | Enabled (MbedTLS default) | N/A | No | The implementation of RFC 6979 in OpenSSL is still work-in-progress (https://github.com/openssl/openssl/pull/9223). |
MBEDTLS_KEY_EXCHANGE_PSK_ENABLED | Disabled (not providing perfect forward secrecy and not recommended for future use) | OPENSSL_NO_PSK | Yes | OE disables PSK on OpenSSL with the `no-psk` configuration. |
MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED | Disabled (not providing perfect forward secrecy and not recommended for future use) | OPENSSL_NO_PSK | Yes | OE disables PSK on OpenSSL with the `no-psk` configuration. |
MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED | Disabled (not providing perfect forward secrecy and not recommended for future use) | OPENSSL_NO_PSK | Yes | OE disables PSK on OpenSSL with the `no-psk` configuration. |
MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED | Disabled (not providing perfect forward secrecy and not recommended for future use)| OPENSSL_NO_PSK | Yes | OE disables PSK on OpenSSL with the `no-psk` configuration. |
MBEDTLS_KEY_EXCHANGE_RSA_ENABLED | Disabled (Deprecated in v0.7, developers should consider ECDHE key exchange instead for forward secrecy) | N/A | No | The following ciphersuites are always supported by OpenSSL (assuming Camellia is enabled): `RSA_WITH_AES_256_GCM_SHA384`, `RSA_WITH_AES_256_CBC_SHA`, `RSA_WITH_CAMELLIA_256_CBC_SHA256`, `RSA_WITH_CAMELLIA_256_CBC_SHA`, `RSA_WITH_AES_128_GCM_SHA256`, `RSA_WITH_AES_128_CBC_SHA`, `RSA_WITH_CAMELLIA_128_CBC_SHA256`, and `RSA_WITH_CAMELLIA_128_CBC_SHA`. |
MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED | Disabled (Not supported in favor of ECDHE for performance) | N/A | No | The following ciphersuites are always supported by OpenSSL (assuming Camellia is enabled): `DHE_RSA_WITH_AES_256_GCM_SHA384`, `DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256`, `DHE_RSA_WITH_CAMELLIA_256_CBC_SHA`, `DHE_RSA_WITH_AES_128_GCM_SHA256`, `DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256`, and `DHE_RSA_WITH_CAMELLIA_128_CBC_SHA`. |
MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED | Enabled | N/A | Yes | OpenSSL always supports ECDHE-RSA based ciphersuites by default. |
MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED | Enabled | N/A | Yes | OpenSSL always supports ECDHE-ECDSA based ciphersuites by default. |
MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED | Disabled (OE's choice to drop uncommon protocols to minimize TCB) | N/A | No | OpenSSL always supports ECDH-ECDSA based ciphersuites by default. Cannot be disabled by OE. |
MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED | Disabled  (OE's choice to drop uncommon protocols to minimize TCB) | N/A | No | OpenSSL always supports ECDH-ECDSA based ciphersuites by default. Cannot be disabled by OE. |
MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED | Disabled (MbedTLS default) | N/A | Yes | The support of J-PAKE on OpenSSL has been removed from v1.1.0. |
MBEDTLS_PK_PARSE_EC_EXTENDED | Disabled (OE's choise to drop support for non-standard EC curve) | N/A | Yes | OpenSSL does not support RFC 5915 + 5480 key formats.  |
MBEDTLS_PKCS1_V15 | Enabled | N/A | Yes | OpenSSL supports PKCS#1 1.5 encoding by default. |
MBEDTLS_PKCS1_V21 | Enabled | N/A | Yes | OpenSSL supports PKCD#1 2.1 encoding by default. |
MBEDTLS_RSA_NO_CRT | Disabled (MbedTLS default) | N/A | Yes | Default OpenSSL behavior is to use Chinese Remainder Theorem in RSA, so while OpenSSL does not support disabling its use, it has parity behavior in OE with mbedTLS. |
MBEDTLS_AESNI_C | Enabled | AES_ASM | Yes | OE keeps the default configuration of OpenSSL that enables assembly-based implementation of AES, which uses AESNI instructions. |
MBEDTLS_AES_C | Enabled | N/A | Yes | OpenSSL supports AES by default. |
MBEDTLS_ARC4_C | Disabled | OPENSSL_NO_RC4 | Yes | OE disables RC4 on OpenSSL with the `no-rc4` configuration. |
MBEDTLS_BLOWFISH_C | Disabled (OE's choice to drop the uncommon cipher) | OPENSSL_NO_BF | Yes | OE disables BlowFish on OpenSSL with the `no-bf` configuration. |
MBEDTLS_CAMELLIA_C | Disabled (OE's choice to drop the uncommon cipher) | OPENSSL_NO_CAMELLIA | Yes | OE disables Camellia on OpenSSL with the `no-camellia` configuration. |
MBEDTLS_ARIA_C | Disabled (OE's choice to drop the uncommon cipher) | OPENSSL_NO_ARIA | Yes | OE disables ARIA on OpenSSL with the `no-aria` configuration. |
MBEDTLS_CCM_C | Enabled (MbedTLS default) | N/A | Yes | OpenSSL always support CCM mode. |
MBEDTLS_CHACHA20_C | Disabled (OE's choice) | OPENSSL_NO_CHACHA | Yes | OE disables CHACHA on OpenSSL with the `no-chacha` configuration. |
MBEDTLS_CHACHAPOLY_C | Disabled (OE's choice) | OPENSSL_NO_CHACHA | Yes | OE disables CHACHA on OpenSSL with the `no-chacha` configuration. |
MBEDTLS_CMAC_C | Enabled (by OE as CMAC is broadly used and allowed by NIST SP standards) | !OPENSSL_NO_CMAC | Yes | OE keeps the default configuration of OpenSSL that enables CMAC. |
MBEDTLS_DES_C | Enabled (for backward compatibility as some protocols use it such as payment industry protocols) | !OPENSSL_NO_DES | Yes | OE keeps the default configuration of OpenSSL that enables DES. |
MBEDTLS_ECDH_C | Enabled | !OPENSSL_NO_EC | Yes | OE keeps the default configuration of OpenSSL that enables ECDH. |
MBEDTLS_ECDSA_C | Enabled | !OPENSSL_NO_EC | Yes | OE keeps the default configuration of OpenSSL that enables ECDSA. |
MBEDTLS_ECJPAKE_C | Disabled | N/A | Yes | OpenSSL does not support JPAKE (removed in v1.1.0). |
MBEDTLS_ECP_C | Enabled | N/A | Yes | OpenSSL supports EC over GF(p) by default. |
MBEDTLS_GCM_C | Enabled | N/A | Yes | OpenSSL supports GCM mode by default. |
MBEDTLS_HKDF_C | Enabled | N/A | Yes | OpenSSL supports HKDF by default (started from v1.1.0). |
MBEDTLS_NIST_KW_C | Disabled | N/A | No | OpenSSL supports key wrapping by default. Cannot disabled by OE. |
MBEDTLS_MD_C | Enabled | N/A | Yes | OpenSSL supports MD APIs by default. |
MBEDTLS_MD2_C | Disabled | OPENSSL_NO_MD2 | Yes | OE disables MD2 on OpenSSL with the `no-md2` configuration. |
MBEDTLS_MD4_C | Disabled | OPENSSL_NO_MD4 | Yes | OE disables MD4 on OpenSSL with the `no-md4` configuration. |
MBEDTLS_MD5_C | Enabled (MbedTLS default, OE doesn't override this because it is still commonly used for backwards compatibility) | !OPENSSL_NO_MD5 | Yes | OE keeps the default configuration of OpenSSL that enables MD5. |
MBEDTLS_PKCS5_C | Enabled | N/A | Yes | OpenSSL supports PKCS#5 by default. |
MBEDTLS_PKCS11_C | Disabled | N/A | Yes | OpenSSL does not support PKCS#11 by default. |
MBEDTLS_PKCS12_C | Enabled | N/A | Yes | OpenSSL supports PKCS#12 by default. |
MBEDTLS_POLY1305_C | Disabled (OE's choice to drop the uncommon hash algorithm to minimize TCB) | OPENSSL_NO_POLY1305 | Yes | OE disables Poly1305 on OpenSSL with the `no-poly1305` configuration. |
MBEDTLS_RIPEMD160_C | Disabled (OE's choice to drop the uncommon hash algorithm to minimize TCB) | OPENSSL_NO_RMD160 | Yes | OE disables on OpenSSL with the `no-rmd160` configuration. |
MBEDTLS_RSA_C | Enabled | N/A | Yes | OpenSSL supports RSA be default. |
MBEDTLS_SHA1_C | Enabled | N/A | Yes | OpenSSL supports SHA1 by default. |
MBEDTLS_SHA256_C | Enabled | N/A | Yes | OpenSSL supports SHA256 by default. |
MBEDTLS_SHA512_C | Enabled | N/A | Yes | OpenSSL supports SHA512 by default. |
MBEDTLS_XTEA_C | Disabled (OE's choice to drop the uncommon cipher to minimize TCB) | N/A | Yes | OpenSSL does not support XTEA by default. |

## OpenSSL-specific Configuration

OpenSSL option | OE Configuration | Comment
|:---|:---|:---|
OPENSSL_NO_BLAKE2 | Disabled | Blake2 hash is not supported by Mbed TLS. OE disables it on OpenSSL with the `no-blake2` configuration to minimize TCB. |
OPENSSL_NO_CAST | Disabled | CAST5 block cipher is not supported by MbedTLS. OE disables it  on OpenSSL with the `no-cast` configuration to minimize TCB. |
OPENSSL_NO_GOST | Disabled | Russian GOST crypto engine is not supported by Mbed TLS. Require dynamic loading and therefore not supported by the OE. OE disables it on OpenSSL with the `no-gost` configuration. |
OPENSSL_NO_MDC2 | Disabled | Modification Detection Code 2 is not supported by mbedTLS. OE disables it on OpenSSL with `no-mdc2` configuration to minimize TCB. |
OPENSSL_NO_WHIRLPOOL | Disabled | Whirlpool hash is not suppored by MbedTLS. OE disables it on OpenSSL with the `no-whirlpool` configuration to minimize TCB. |
OPNESSL_NO_IDEA | Disabled | IDEA block cipher is not supported by MbedTLS. OE disables it on OpenSSL with the `no-idea` configuration to minimize TCB. |
OPENSSL_NO_SEED | Disabled | SEED ciphersuites (RFC 4162) are not supported by MbedTLS. OE disables it on OpenSSL with the `no-seed` configuration to minimize TCB. |
OPENSSL_NO_SCRYPT | Disabled | The scrypt KDF is not supported by MbedTLS. OE disables it on OpenSSL with the `no-scrypt` configuration to minimize TCB. |
OPENSSL_NO_SM2 | Disabled | Chinese cryptographic algorithm(s) are not supported by MbedTLS. OE disables it on OpenSSL with the `no-sm2` configuration. |
OPENSSL_NO_SM3 | Disabled | Chinese cryptographic algorithm(s) are not supported by MbedTLS. OE disables it on OpenSSL with the `no-sm3` configuration. |
OPENSSL_NO_SM4 | Disabled | Chinese cryptographic algorithm(s) are not supported by MbedTLS. OE disables it on OpenSSL with the `no-sm4` configuration. |
OPENSSL_NO_SRP | Disabled | Secure remote password (SRP) is not supported by MbedTLS. OE disables it on OpenSSL with the `no-srp` configuration. |
OPENSSL_NO_SIPHASH | Disabled | SipHash is not supported by MbedTLS. OE disables it on OpenSSL with the `no-siphash` configuration to minimize TCB. |
