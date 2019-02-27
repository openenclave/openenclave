// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _CRYPTO_ENCLAVE_RANDOM_H
#define _CRYPTO_ENCLAVE_RANDOM_H

/* Nest mbedtls header includes with required corelibc defines */
// clang-format off
#include "mbedtls_corelibc_defs.h"
#include <mbedtls/ctr_drbg.h>
#include "mbedtls_corelibc_undef.h"
// clang-format on

mbedtls_ctr_drbg_context* oe_mbedtls_get_drbg();

#endif /* _CRYPTO_ENCLAVE_RANDOM_H */
