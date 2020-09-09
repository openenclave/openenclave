// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>

/* Refer to openssl/crypto.h for the original definitions */
#define OE_OPENSSL_INIT_NO_LOAD_CONFIG 0x00000080L

/* Forward declarion */
typedef struct oe_openssl_init_settings OE_OPENSSL_INIT_SETTINGS;
int OE_OPENSSL_init_crypto(
    uint64_t opts,
    const OE_OPENSSL_INIT_SETTINGS* settings);

/*
 * Weak implementation that prevents link-time errors when an enclave
 * does not link against OpenSSL libraries.
 */
int OE_OPENSSL_init_crypto(
    uint64_t opts,
    const OE_OPENSSL_INIT_SETTINGS* settings)
{
    OE_UNUSED(opts);
    OE_UNUSED(settings);
    return 0;
}
OE_WEAK_ALIAS(OE_OPENSSL_init_crypto, OPENSSL_init_crypto);

/*
 * Define the function as a constructor that ensures it is invoked before
 * any OpenSSL APIs. Note that the constructor is only included by the linker
 * when an enclave links against OpenSSL libraries (i.e., the
 * OPENSSL_init_crypto symbol is included in the binary); i.e., when the enclave
 * does not link against OpenSSL libraries, the constructor is discarded by the
 * linker.
 */
__attribute__((constructor)) void oe_openssl_init()
{
    /*
     * Invoke the API with the OPENSSL_INIT_NO_LOAD_CONFIG option effectively
     * nullifies the OPENSSL_INIT_LOAD_CONFIG option. This prevents users to
     * explicitly configure an OpenSSL application to load openssl.cnf from
     * the host filesystem, which is considered as untrusted under the threat
     * model of TEE.
     */
    OPENSSL_init_crypto(OE_OPENSSL_INIT_NO_LOAD_CONFIG, NULL);
}
