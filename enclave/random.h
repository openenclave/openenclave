// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _CRYPTO_ENCLAVE_RANDOM_H
#define _CRYPTO_ENCLAVE_RANDOM_H

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <mbedtls/ctr_drbg.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

mbedtls_ctr_drbg_context* oe_mbedtls_get_drbg();

#endif /* _CRYPTO_ENCLAVE_RANDOM_H */
