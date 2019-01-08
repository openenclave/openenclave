/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#define WOLFSSL_BASE64_ENCODE  // for wolfMQTT
#define WOLFSSL_SHA512 // for azure iot hub
//#define DEBUG_WOLFSSL

#include "wolf_config.h"

/* Configurations */
#if defined(HAVE_FIPS)
/* FIPS */
#define OPENSSL_EXTRA
#define HAVE_THREAD_LS
#define WOLFSSL_KEY_GEN
#define HAVE_AESGCM
#define HAVE_HASHDRBG
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_PSK
#define NO_HC128
#define NO_RC4
#define NO_RABBIT
#define NO_DSA
#define NO_MD4
#elif defined(WOLFSSL_LIB)
/* The lib */
#define OPENSSL_EXTRA
#define WOLFSSL_RIPEMD
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_PSK
#define HAVE_EXTENDED_MASTER
#define WOLFSSL_SNIFFER
#define HAVE_TLS_EXTENSIONS
#define HAVE_SECURE_RENEGOTIATION
#else
/* The servers and clients */
#define OPENSSL_EXTRA
#define NO_PSK
#endif /* HAVE_FIPS */

#undef WOLFSSL_RIPEMD

#define HAVE_ECC
#define WOLFSSL_ALWAYS_VERIFY_CB
#define NO_FILESYSTEM
#define SESSION_CERTS
#define WOLFSSL_ALT_CERT_CHAINS
#define WOLF_OSSL_WORKAROUND
#define WOLFSSL_KEY_GEN
#define WOLFSSL_AES_DIRECT
