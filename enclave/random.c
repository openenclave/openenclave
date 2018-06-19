// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "random.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/bits/thread.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/random.h>

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

static mbedtls_ctr_drbg_context _drbg;
static mbedtls_entropy_context _entropy;

static oe_result_t _SeedEntropySource()
{
    oe_result_t result = OE_UNEXPECTED;

    mbedtls_ctr_drbg_init(&_drbg);
    mbedtls_entropy_init(&_entropy);

    OE_CHECK(
        mbedtls_ctr_drbg_seed(
            &_drbg, mbedtls_entropy_func, &_entropy, NULL, 0));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _seedResult = OE_UNEXPECTED;
static oe_once_t _seedOnce = OE_ONCE_INITIALIZER;

/* Wrapper to set file-scope _seedResult */
static void _SeedEntropySourceOnce()
{
    _seedResult = _SeedEntropySource();
}

mbedtls_ctr_drbg_context* oe_mbedtls_get_drbg()
{
    oe_once(&_seedOnce, _SeedEntropySourceOnce);
    return &_drbg;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

oe_result_t oe_random(void* data, size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    int rc;

    /* Seed the entropy source on the first call */
    {
        oe_once(&_seedOnce, _SeedEntropySourceOnce);
        OE_CHECK(_seedResult);
    }

    /* Generate random data (synchronize access to _drbg instance) */
    rc = mbedtls_ctr_drbg_random(&_drbg, data, size);

    if (rc != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    return result;
}
