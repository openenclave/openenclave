// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_OPENSSL_SSL_UNSUPPORTED_H
#define _OE_OPENSSL_SSL_UNSUPPORTED_H

#if !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED)

#include <openssl/unsupported.h>

/*
**==============================================================================
**
** <openssl/ssl.h>
**
**==============================================================================
*/

/*
 * The following OpenSSL 1.0+ APIs allow users to configure an OpenSSL
 * application to look up certificates from the host filesystem, which is not
 * trusted in OE's threat model, and therefore are recommended not to use inside
 * an enclave.
 */

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx);
#define SSL_CTX_set_default_verify_paths \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_set_default_verify_paths)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_set_default_verify_dir(SSL_CTX* ctx);
#define SSL_CTX_set_default_verify_dir \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_set_default_verify_dir)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_set_default_verify_file(SSL_CTX* ctx);
#define SSL_CTX_set_default_verify_file \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_set_default_verify_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_load_verify_locations(
    SSL_CTX* ctx,
    const char* CAfile,
    const char* CApath);
#define SSL_CTX_load_verify_locations \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_load_verify_locations)

/*
 * The following OpenSSL 3.0+ APIs allow users to configure an OpenSSL
 * application to look up certificates from the host filesystem or URL store,
 * which is not trusted in OE's threat model, and recommended not to use inside
 * an enclave.
 */

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_set_default_verify_store(SSL_CTX* ctx);
#define SSL_CTX_set_default_verify_store \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_set_default_verify_store)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_load_verify_dir(SSL_CTX* ctx, const char* CApath);
#define SSL_CTX_load_verify_dir OE_OPENSSL_RAISE_ERROR(SSL_CTX_load_verify_dir)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_load_verify_file(SSL_CTX* ctx, const char* CAfile);
#define SSL_CTX_load_verify_file \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_load_verify_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int SSL_CTX_load_verify_store(SSL_CTX* ctx, const char* CAstore);
#define SSL_CTX_load_verify_store \
    OE_OPENSSL_RAISE_ERROR(SSL_CTX_load_verify_store)

#endif /* !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED) */
#endif /* _OE_OPENSSL_SSL_UNSUPPORTED_H */
