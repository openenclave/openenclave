// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "random.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/random.h>
#include <openenclave/internal/thread.h>

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

static mbedtls_ctr_drbg_context _drbg;
static mbedtls_entropy_context _entropy;

static oe_result_t _seed_entropy_source()
{
    oe_result_t result = OE_UNEXPECTED;

    mbedtls_ctr_drbg_init(&_drbg);
    mbedtls_entropy_init(&_entropy);

    OE_CHECK(
        (oe_result_t)mbedtls_ctr_drbg_seed(
            &_drbg, mbedtls_entropy_func, &_entropy, NULL, 0));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _seed_result = OE_UNEXPECTED;
static oe_once_t _seed_once = OE_ONCE_INIT;

/* Wrapper to set file-scope _seed_result */
static void _seed_entropy_source_once()
{
    _seed_result = _seed_entropy_source();
}

mbedtls_ctr_drbg_context* oe_mbedtls_get_drbg()
{
    oe_once(&_seed_once, _seed_entropy_source_once);
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
    /* For now just call oe_random_internal.  In the future, this should
     * return a cryptographically random set of bytes.
     */
    return oe_random_internal(data, size);
}

oe_result_t oe_random_internal(void* data, size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    int rc;

    /* Seed the entropy source on the first call */
    {
        oe_once(&_seed_once, _seed_entropy_source_once);
        OE_CHECK(_seed_result);
    }

    /* Generate random data (synchronize access to _drbg instance) */
    rc = mbedtls_ctr_drbg_random(&_drbg, data, size);
    if (rc != 0)
        OE_RAISE_MSG(OE_FAILURE, "rc = 0x%x\n", rc);

    result = OE_OK;
done:

    return result;
}
