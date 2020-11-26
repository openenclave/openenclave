// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openssl/engine.h>
static oe_once_t _openssl_initialize_once;
static ENGINE* eng;

static void _finalize(void)
{
    if (eng)
    {
        ENGINE_finish(eng);
        ENGINE_free(eng);
        ENGINE_cleanup();
        eng = NULL;
    }
}

static void _initialize_rdrand_engine()
{
    int rc = 0;

    /* Initialize rdrand engine. */
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
        goto done;

    rc = ENGINE_init(eng);
    if (rc == 0)
        goto done;

    rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    if (rc == 0)
        goto done;

    if (!atexit(_finalize))
        goto done;

    rc = 1;

done:
    if (rc == 0)
    {
        OE_TRACE_ERROR("OpenSSL initialization failed");
        _finalize();
    }
    return;
}

static void _initialize(void)
{
    /*
     * OpenSSL in the enclave requires us to explicitly register the RDRAND
     * engine.
     */
    _initialize_rdrand_engine();
}

void oe_crypto_initialize(void)
{
    oe_once(&_openssl_initialize_once, _initialize);
}
