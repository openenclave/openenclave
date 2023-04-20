// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openssl/engine.h>
static oe_once_t _openssl_initialize_once;
int _is_symcrypt_engine_available = 0;

#define HOST_ENTROPY_TEST_SIZE 16

/* Forward declarations */
int SCOSSL_ENGINE_Initialize();
int oe_sgx_get_additional_host_entropy(uint8_t*, size_t);

static int _initialize_symcrypt_engine()
{
    int result;

    result = SCOSSL_ENGINE_Initialize();
    if (result != OE_SYMCRYPT_ENGINE_SUCCESS)
        goto done;

done:
    if (result == OE_SYMCRYPT_ENGINE_FAIL)
        OE_TRACE_ERROR("SymCrypt engine initialization failed");

    return (result == OE_SYMCRYPT_ENGINE_SUCCESS) ? 1 : 0;
}

static void _initialize(void)
{
    OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    /* _initialize_symcrypt_engine only registers the SymCrypt engine and
     * returns 1 if the enclave opts into the engine at link-time. Otherwise,
     * the weak implementation of the function is used, which always returns 0.
     */
    _is_symcrypt_engine_available = _initialize_symcrypt_engine();

    if (_is_symcrypt_engine_available)
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
