// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _CRYPTO_ENCLAVE_CTR_DRBG_H
#define _CRYPTO_ENCLAVE_CTR_DRBG_H

#include <mbedtls/ctr_drbg.h>

mbedtls_ctr_drbg_context* oe_mbedtls_get_drbg();

#endif /* _CRYPTO_ENCLAVE_CTR_DRBG_H */
