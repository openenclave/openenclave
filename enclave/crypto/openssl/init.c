// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openssl/engine.h>
static oe_once_t _openssl_initialize_once;
static ENGINE* eng;
int is_symcrypt_engine_available = 0;

/* Forward declaration */
int SYMCRYPT_ENGINE_Initialize();

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

static int _initialize_symcrypt_engine()
{
    int rc = 0;

    /* The actual implementation of SYMCRYPT_ENGINE_Initialize
     * always returns 1. */
    if (SYMCRYPT_ENGINE_Initialize() != 1)
        goto done;

    rc = 1;

    OE_TRACE_INFO("SymCrypt engine is registered");

done:
    return rc;
}

static void _initialize(void)
{
    /* _initialize_symcrypt_engine only registers the SymCrypt engine and
     * returns 1 if the enclave opts into the engine at link-time. Otherwise,
     * the weak implementation of the function is used, which always returns 0.
     */
    is_symcrypt_engine_available = _initialize_symcrypt_engine();

    if (!is_symcrypt_engine_available)
    {
        /* Explicitly register the RDRAND engine if the SymCrypt engine
         * is not available, which provides its own RAND implementation. */
        _initialize_rdrand_engine();
    }
}

void oe_crypto_initialize(void)
{
    oe_once(&_openssl_initialize_once, _initialize);
}

int oe_is_symcrypt_engine_available()
{
    return is_symcrypt_engine_available;
}
