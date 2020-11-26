// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/crypto/init.h>

/*
 * oe_crypto_initialize will be invoked during the enclave initialization.
 * Do nothing here given that Mbed TLS does not require initialization
 * (while OpenSSL does).
 */
void oe_crypto_initialize(void)
{
}
