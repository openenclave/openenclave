// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_OPENSSL_CRYPTO_UNSUPPORTED_H
#define _OE_OPENSSL_CRYPTO_UNSUPPORTED_H

#if !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED)

#include <openssl/unsupported.h>

OE_OPENSSL_EXTERN_C_BEGIN

/*
**==============================================================================
**
** <openssl/crypto.h>
**
**==============================================================================
*/

/*
 * The following macro allows users to configure an OpenSSL application (via
 * OPENSSL_init_crypto or OPENSSL_init_ssl) to lookup a configuration file from
 * the host filesystem, which is not trusted in OE's threat model, and therefore
 * is recommended not to use inside an enclave.
 */

#ifdef OPENSSL_INIT_LOAD_CONFIG
#undef OPENSSL_INIT_LOAD_CONFIG
OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_MACRO)
static inline unsigned long OPENSSL_INIT_LOAD_CONFIG()
{
    return 0x00000040L;
}
#define OPENSSL_INIT_LOAD_CONFIG \
    OE_OPENSSL_RAISE_ERROR(OPENSSL_INIT_LOAD_CONFIG)
#endif

OE_OPENSSL_EXTERN_C_END

#endif /* !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED) */
#endif /* _OE_OPENSSL_CRYPTO_UNSUPPORTED_H */
