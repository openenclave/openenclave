// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once

// Includes for mbedtls shipped with oe.
// Also add the following libraries to your linker command line:
// -loeenclave -lmbedcrypto -lmbedtls -lmbedx509
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include "log.h"

bool init_mbedtls(void);
void cleanup_mbedtls(void);

/**
 * Compute the sha256 hash of given data.
 */
int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32]);