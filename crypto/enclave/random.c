// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "random.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/random.h>
#include <openenclave/bits/raise.h>
#include <openenclave/enclave.h>
#include <openenclave/thread.h>

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

static mbedtls_ctr_drbg_context _drbg;
static bool _seeded = false;

static OE_Result _SeedEntropySource()
{
    OE_Result result = OE_UNEXPECTED;
    static OE_Mutex _mutex = OE_MUTEX_INITIALIZER;
    static mbedtls_entropy_context _entropy;

    if (_seeded == false)
    {
        OE_MutexLock(&_mutex);

        if (_seeded == false)
        {
            mbedtls_ctr_drbg_init(&_drbg);
            mbedtls_entropy_init(&_entropy);

            if (mbedtls_ctr_drbg_seed(
                    &_drbg, mbedtls_entropy_func, &_entropy, NULL, 0) != 0)
            {
                OE_MutexUnlock(&_mutex);
                OE_RAISE(OE_FAILURE);
            }

            _seeded = true;
        }

        OE_MutexUnlock(&_mutex);
    }

    result = OE_OK;

done:
    return result;
}

static mbedtls_ctr_drbg_context _drbg;

mbedtls_ctr_drbg_context* OE_MBEDTLS_GetDrbg()
{
    if (_seeded == false)
    {
        if (_SeedEntropySource() != OE_OK)
            return NULL;
    }

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
    if (_seeded == false)
    {
        if (_SeedEntropySource() != OE_OK)
            OE_RAISE(OE_FAILURE);
    }

    /* Generate random data (synchronize acceess to _drbg instance) */
    rc = mbedtls_ctr_drbg_random(&_drbg, data, size);

    if (rc != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    return result;
}
