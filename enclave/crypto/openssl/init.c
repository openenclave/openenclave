// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openssl/engine.h>
static oe_once_t _openssl_initialize_once;
static ENGINE* _rdrand_engine;
int _is_symcrypt_engine_available = 0;

#define HOST_ENTROPY_TEST_SIZE 16

/* Forward declarations */
int SC_OSSL_ENGINE_Initialize();
int oe_sgx_get_additional_host_entropy(uint8_t*, size_t);

static void _finalize(void)
{
    if (_rdrand_engine)
    {
        ENGINE_finish(_rdrand_engine);
        ENGINE_free(_rdrand_engine);
        ENGINE_cleanup();
        _rdrand_engine = NULL;
    }
}

static void _initialize_rdrand_engine()
{
    int result = 0;

    /* Initialize rdrand engine. */
    ENGINE_load_rdrand();
    _rdrand_engine = ENGINE_by_id("rdrand");
    if (_rdrand_engine == NULL)
        goto done;

    result = ENGINE_init(_rdrand_engine);
    if (result == 0)
        goto done;

    result = ENGINE_set_default(_rdrand_engine, ENGINE_METHOD_RAND);
    if (result == 0)
        goto done;

    if (!atexit(_finalize))
        goto done;

    result = 1;

done:
    if (result == 0)
    {
        OE_TRACE_ERROR("OpenSSL initialization failed");
        _finalize();
    }
    return;
}

static int _initialize_symcrypt_engine()
{
    int result;

    result = SC_OSSL_ENGINE_Initialize();
    if (result != OE_SYMCRYPT_ENGINE_SUCCESS)
        goto done;

done:
    if (result == OE_SYMCRYPT_ENGINE_FAIL)
        OE_TRACE_ERROR("SymCrypt engine initialization failed");

    return (result == OE_SYMCRYPT_ENGINE_SUCCESS) ? 1 : 0;
}

static void _initialize(void)
{
    /* _initialize_symcrypt_engine only registers the SymCrypt engine and
     * returns 1 if the enclave opts into the engine at link-time. Otherwise,
     * the weak implementation of the function is used, which always returns 0.
     */
    _is_symcrypt_engine_available = _initialize_symcrypt_engine();

    if (!_is_symcrypt_engine_available)
    {
        /* Explicitly register the RDRAND engine if the SymCrypt engine
         * is not available, which provides its own RAND implementation. */
        _initialize_rdrand_engine();
    }
    else
    {
        uint8_t data[HOST_ENTROPY_TEST_SIZE];
        /* Enforce the invocation of oe_sgx_get_additional_host_entropy,
         * which will cause an enclave abort if the entropy.edl has not been
         * included properly */
        oe_sgx_get_additional_host_entropy(data, HOST_ENTROPY_TEST_SIZE);
    }
}

void oe_crypto_initialize(void)
{
    oe_once(&_openssl_initialize_once, _initialize);
}

int oe_is_symcrypt_engine_available()
{
    return _is_symcrypt_engine_available;
}
