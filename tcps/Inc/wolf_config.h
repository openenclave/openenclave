/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
// Common Crypto settings for wolf config.
// this is to help align different platforms to a default / minimal
// list of crypto suites that will support OTS and Azure Iot TLS connections.
// Any platform can expand this list as needed.


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* ECC */
#if 1
    #undef  HAVE_ECC
    #define HAVE_ECC

    #if 1
        /* Manually define enabled curves */
        #undef  ECC_USER_CURVES
        #define ECC_USER_CURVES

        //#define HAVE_ECC192
        //#define HAVE_ECC224
        #undef NO_ECC256
        //#define HAVE_ECC384
        //#define HAVE_ECC521
    #endif

    /* Fixed point cache (speeds repeated operations against same private key) */
    #undef  FP_ECC
    //#define FP_ECC
    #ifdef FP_ECC
        /* Bits / Entries */
        #undef  FP_ENTRIES
        #define FP_ENTRIES  2
        #undef  FP_LUT
        #define FP_LUT      4
    #endif

    /* Optional ECC calculation method */
    /* Note: doubles heap usage, but slightly faster */
    #undef  ECC_SHAMIR
    //#define ECC_SHAMIR

    /* Reduces heap usage, but slower */
    // TODO:: Why is ECC_TIMING_RESISTANT disabled??? Doesnt it open up for timing based attacks?
    // Is this related to low memory on STM?
    #define WC_NO_HARDEN // Needs to be set if ECC_TIMING_RESISTANT is not defined. 
    #undef  ECC_TIMING_RESISTANT
    //#define ECC_TIMING_RESISTANT

    #ifdef USE_FAST_MATH
        /* use reduced size math buffers for ecc points */
        #undef  ALT_ECC_SIZE
        #define ALT_ECC_SIZE

        /* optionally override the default max ecc bits */
        //#undef  FP_MAX_BITS_ECC
        //#define FP_MAX_BITS_ECC     512

        /* Enable TFM optimizations for ECC */
        //#define TFM_ECC192
        //#define TFM_ECC224
        //#define TFM_ECC256
        //#define TFM_ECC384
        //#define TFM_ECC521
    #endif
#endif


#undef NO_RSA
#if 1
    #ifdef USE_FAST_MATH
        /* Maximum math bits (Max RSA key bits * 2) */
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS     4096
    #endif

    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
    #undef  WC_RSA_BLINDING
    #define WC_RSA_BLINDING

#else
    #define NO_RSA
#endif

/* AES */
#undef NO_AES
#if 1
    //#define HAVE_AESGCM
    #ifdef HAVE_AESGCM
        #define NO_AES_DECRYPT
        #define HAVE_AESGCM_DECRYPT
    #endif

    /* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    #undef  GCM_SMALL
    #define GCM_SMALL

    #undef  GCM_TABLE
    //#define GCM_TABLE
#else
    #define NO_AES
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 0
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if 0
    #define HAVE_CURVE25519
    #define HAVE_ED25519

    /* Optionally use small math (less flash usage, but much slower) */
    #if 0
        #define CURVED25519_SMALL
    #endif
#endif

#undef  NO_DES3
#define NO_DES3

#undef  NO_RC4
#define NO_RC4

#undef  NO_HC128
#define NO_HC128

#undef  NO_PWDBASED
//#define NO_PWDBASED

#undef  NO_PSK
#define NO_PSK

#undef  NO_RABBIT
#define NO_RABBIT

/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 0
    /* 1k smaller, but 25% slower */
    #define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 0
    #define WOLFSSL_SHA512

    /* Sha384 */
    #undef  WOLFSSL_SHA384
    #if 1
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA2
#endif

/* MD4 */
#undef  NO_MD4
#if 0
    /* enabled */
#else
    #define NO_MD4
#endif

/* MD5 */
#undef  NO_MD5
#if 0
    /* enabled */
#else
    #define NO_MD5
#endif

/* DSA */
#undef  NO_DSA
#if 0
    /* enabled */
#else
    #define NO_DSA
#endif

/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#define OPENSSL_EXTRA
#define WOLFSSL_DTLS
#define WOLFSSL_USER_IO

/* TLS Session Cache */
#if 0
    #define SMALL_SESSION_CACHE
#else
// TODO: NO_SESSION_CACHE is ok for SSL clients but it might impact
// performance when running wolfssl on the server side. For services like 
// OTS and RM, client sessions are short lived and clients rarely re-connect 
// to the service immediately. However, a TCPS based logging service might see 
// longer sessions from clients as well as resuming of sessions. In this 
// case, a session cache can help improve service performance.
    #define NO_SESSION_CACHE
#endif

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_WRITEV
#define NO_WRITEV

#undef  NO_MAIN_DRIVER
//#define NO_MAIN_DRIVER

#undef  NO_DEV_RANDOM
//#define NO_DEV_RANDOM

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_CODING // Base64_Decode support needed
//#define NO_CODING

#undef  WOLFSSL_NO_SOCK
#define WOLFSSL_NO_SOCK
