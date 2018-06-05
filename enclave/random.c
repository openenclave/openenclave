// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "random.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/random.h>
#include <openenclave/thread.h>

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

static mbedtls_ctr_drbg_context _drbg;
static mbedtls_entropy_context _entropy;

static OE_Result _SeedEntropySource()
{
    OE_Result result = OE_UNEXPECTED;

    mbedtls_ctr_drbg_init(&_drbg);
    mbedtls_entropy_init(&_entropy);

    OE_CHECK(
        mbedtls_ctr_drbg_seed(
            &_drbg, mbedtls_entropy_func, &_entropy, NULL, 0));

    result = OE_OK;

done:
    return result;
}

static OE_Result _seedResult = OE_UNEXPECTED;
static OE_OnceType _seedOnce = OE_ONCE_INITIALIZER;

/* Wrapper to set file-scope _seedResult */
static void _SeedEntropySourceOnce()
{
    _seedResult = _SeedEntropySource();
}

mbedtls_ctr_drbg_context* OE_MBEDTLS_GetDrbg()
{
    OE_Once(&_seedOnce, _SeedEntropySourceOnce);
    return &_drbg;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

OE_Result OE_Random(void* data, size_t size)
{
    OE_Result result = OE_UNEXPECTED;
    int rc;

    /* Seed the entropy source on the first call */
    {
        OE_Once(&_seedOnce, _SeedEntropySourceOnce);
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
