// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/internal/print.h>
#include "utility.h"

oe_result_t generate_certificate_and_pkey(
    mbedtls_x509_crt* cert,
    mbedtls_pk_context* private_key);

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags);

// mbedtls debug levels: 0 No debug, 1 Error, 2 State change, 3 Informational, 4
// Verbose
#define DEBUG_LEVEL 1