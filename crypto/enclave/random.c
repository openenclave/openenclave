// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/random.h>
#include <openenclave/bits/trace.h>
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
static mbedtls_entropy_context _entropy;
static bool _seeded = false;

static OE_Result _SeedEntropySource()
{
    OE_Result result = OE_UNEXPECTED;
    static OE_Mutex _mutex = OE_MUTEX_INITIALIZER;

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
                OE_THROW(OE_FAILURE);
            }

            _seeded = true;
        }

        OE_MutexUnlock(&_mutex);
    }

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
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
    static OE_Mutex _mutex = OE_MUTEX_INITIALIZER;
    int rc;

    /* Seed the entropy source on the first call */
    if (_seeded == false)
    {
        if (_SeedEntropySource() != OE_OK)
            OE_THROW(OE_FAILURE);
    }

    /* Generate random data (synchronize acceess to _drbg instance) */
    OE_MutexLock(&_mutex);
    rc = mbedtls_ctr_drbg_random(&_drbg, data, size);
    OE_MutexUnlock(&_mutex);

    if (rc != 0)
        OE_THROW(OE_FAILURE);

    OE_THROW(OE_OK);

OE_CATCH:

    return result;
}
