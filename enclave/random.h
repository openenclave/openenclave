// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _CRYPTO_ENCLAVE_RANDOM_H
#define _CRYPTO_ENCLAVE_RANDOM_H

#include <mbedtls/ctr_drbg.h>

mbedtls_ctr_drbg_context* oe_mbedtls_get_drbg();

#endif /* _CRYPTO_ENCLAVE_RANDOM_H */
