/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include "../wolf_config.h"

#include <TrustedWolfssl.h>
#include <optee/ctype_optee_t.h>
#include <optee/string_optee_t.h>

#define WOLFSSL_GENERAL_ALIGNMENT   4
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_USER_IO
#define SIZEOF_LONG_LONG 8

#undef  NO_RSA
#undef  RSA_LOW_MEM

#define WC_RSA_BLINDING
#define ECC_USER_CURVES

#undef  NO_ECC256
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT

#ifdef USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
    #define FP_MAX_BITS     4096
    #define ALT_ECC_SIZE
    #define TFM_ECC256
#endif

#undef NO_AES
#define HAVE_AES_CBC
#define HAVE_AESCCM
#define GCM_SMALL
#define HAVE_AES_DECRYPT

#undef  HAVE_CHACHA
#undef  HAVE_POLY1305
#undef  HAVE_CURVE25519
#undef  HAVE_ED25519
#undef  NO_SHA
#undef  NO_SHA256
#undef  WOLFSSL_SHA384
#undef  NO_MD5
#undef  WOLFSSL_SHA3
#undef  HAVE_HKDF

#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_256

/*
 * DEBUG_WOLFSSL is disabled by default because its log ouput
 * appears to be too verbose for OPTEE.
 */
#undef  DEBUG_WOLFSSL

#ifdef DEBUG_WOLFSSL
    #include <stdio.h>
#else
    #undef  NO_ERROR_STRINGS
    #define NO_ERROR_STRINGS
#endif

#define NO_WOLFSSL_MEMORY

#define CUSTOM_RAND_TYPE      unsigned int

extern unsigned int custom_rand_generate(void);
#define CUSTOM_RAND_GENERATE  custom_rand_generate
#define WC_NO_HASHDRBG

extern int custom_rand_generate_block(unsigned char* output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_BLOCK  custom_rand_generate_block

#undef  KEEP_PEER_CERT
#undef  HAVE_COMP_KEY
#define HAVE_SUPPORTED_CURVES
#define WOLFSSL_BASE64_ENCODE
#define NO_SESSION_CACHE
#define NO_OLD_WC_NAMES

#undef  NO_WOLFSSL_SERVER
#undef  NO_WOLFSSL_CLIENT
#undef  NO_CRYPT_TEST
#undef  NO_CRYPT_BENCHMARK
#undef  NO_INLINE
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_DH
#define NO_DES3
#define NO_OLD_TLS

#define OPENSSL_EXTRA
#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define NO_PSK
#define NO_HC128
#define NO_RC4
#define NO_RABBIT
#define NO_DSA
#define NO_MD4
#define HAVE_TLS_EXTENSIONS
#define NO_PWDBASED

#undef  NO_CODING
#undef  NO_ASN_TIME
#undef  NO_CERTS
#undef  NO_SIG_WRAPPER

#define HAVE_ECC
#define NO_FILESYSTEM
#define WOLF_OSSL_WORKAROUND
#define WOLFSSL_KEY_GEN
#define WOLFSSL_AES_DIRECT
