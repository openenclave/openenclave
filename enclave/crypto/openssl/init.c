// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openssl/engine.h>
#if OECRYPTO_OPENSSL_VER >= 3
#include <openssl/core.h>
#include <openssl/provider.h>
#endif
static oe_once_t _openssl_initialize_once;
int _is_symcrypt_engine_available = 0;
int _is_symcrypt_provider_available = 0;

#define HOST_ENTROPY_TEST_SIZE 16

/* Forward declarations */
#if OECRYPTO_OPENSSL_VER >= 3
int OSSL_provider_init(
    const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in,
    const OSSL_DISPATCH** out,
    void** provctx);
#endif
int SCOSSL_ENGINE_Initialize();
int oe_sgx_get_additional_host_entropy(uint8_t*, size_t);

static int _initialize_symcrypt_engine()
{
    int result;

    result = SCOSSL_ENGINE_Initialize();
    if (result != OE_SYMCRYPT_ENGINE_SUCCESS)
        OE_TRACE_ERROR("SymCrypt engine initialization failed");

    return (result == OE_SYMCRYPT_ENGINE_SUCCESS) ? 1 : 0;
}

#if OECRYPTO_OPENSSL_VER >= 3
static OSSL_PROVIDER* _default_prov;
static OSSL_PROVIDER* _scossl_prov;

static void _finalize_prov(void)
{
    if (_default_prov)
    {
        OSSL_PROVIDER_unload(_default_prov);
        _default_prov = NULL;
    }
    if (_scossl_prov)
    {
        OSSL_PROVIDER_unload(_scossl_prov);
        _scossl_prov = NULL;
    }
}

static int _initialize_symcrypt_provider()
{
    int result;

    // The default provider is loaded first to make sure that OpenSSL can
    // fall back on it when operations not supported by SymCrypt are called
    if (atexit(_finalize_prov) != 0)
    {
        result = 0;
        goto done;
    }

    _default_prov = OSSL_PROVIDER_load(NULL, "default");

    if (_default_prov == NULL)
    {
        result = 0;
        goto done;
    }

    result = OSSL_PROVIDER_add_builtin(
        NULL, "symcrypt_provider", OSSL_provider_init);
    _scossl_prov = OSSL_PROVIDER_load(NULL, "symcrypt_provider");

    if (_scossl_prov == NULL)
    {
        result = 0;
        goto done;
    }

done:
    if (result == 0)
        OE_TRACE_ERROR("OpenSSL provider initialization failed");

    return result;
}
#else
static ENGINE* _rdrand_engine;

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
        OE_TRACE_ERROR("OpenSSL engine initialization failed");
        _finalize();
    }
    return;
}
#endif // OECRYPTO_OPENSSL_VER < 3

static void _initialize(void)
{
#if OECRYPTO_OPENSSL_VER >= 3
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    _is_symcrypt_provider_available = _initialize_symcrypt_provider();
#endif

    /* _initialize_symcrypt_engine only registers the SymCrypt engine and
     * returns 1 if the enclave opts into the engine at link-time. Otherwise,
     * the weak implementation of the function is used, which always returns 0.
     */
    _is_symcrypt_engine_available = _initialize_symcrypt_engine();

    if (_is_symcrypt_engine_available || _is_symcrypt_provider_available)
    {
        uint8_t data[HOST_ENTROPY_TEST_SIZE];
        /* Enforce the invocation of oe_sgx_get_additional_host_entropy,
         * which will cause an enclave abort if the entropy.edl has not been
         * included properly */
        oe_sgx_get_additional_host_entropy(data, HOST_ENTROPY_TEST_SIZE);
    }
#if OECRYPTO_OPENSSL_VER < 3
    else
    {
        _initialize_rdrand_engine();
    }
#endif // OECRYPTO_OPENSSL_VER < 3
}

void oe_crypto_initialize(void)
{
    oe_once(&_openssl_initialize_once, _initialize);
}

int oe_is_symcrypt_engine_available()
{
    return _is_symcrypt_engine_available;
}

int oe_is_symcrypt_provider_available()
{
    return _is_symcrypt_provider_available;
}
