// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_OPENSSL_UNSUPPORTED_H
#define _OE_OPENSSL_UNSUPPORTED_H

#if !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED)

#if defined(__cplusplus)
#define OE_OPENSSL_EXTERN_C_BEGIN \
    extern "C"                    \
    {
#define OE_OPENSSL_EXTERN_C_END }
#else
#define OE_OPENSSL_EXTERN_C_BEGIN
#define OE_OPENSSL_EXTERN_C_END
#endif

#if defined(__GNUC__)
#define OE_OPENSSL_UNSUPPORTED(MSG) __attribute__((deprecated(MSG)))
#else
#define OE_OPENSSL_UNSUPPORTED(MSG)
#endif
#define OE_OPENSSL_RAISE_ERROR(NAME) (OE_OPENSSL_UNSUPPORTED_ERROR, NAME)

OE_OPENSSL_EXTERN_C_BEGIN

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

// clang-format off
#define OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION \
    "The function may be unsafe inside an enclave as it causes the enclave to read " \
    "files from an untrusted host. Please refer to the following link for security guidance.\n\n" \
    "https://github.com/openenclave/openenclave/blob/master/docs/OpenSSLSupport.md#security-guidance-for-using-openssl-apismacros" \
    "\n\nTo use the function anyway, add the -DOE_OPENSSL_SUPPRESS_UNSUPPORTED option when compiling the program."
#define OE_UNSUPPORTED_ENCLAVE_OPENSSL_MACRO \
    "The macro may be unsafe inside an enclave as it causes the enclave to read " \
    "files from an untrusted host. Please refer to the following link for security guidance.\n\n" \
    "https://github.com/openenclave/openenclave/blob/master/docs/OpenSSLSupport.md#security-guidance-for-using-openssl-apismacros" \
    "\n\nTo use the macro anyway, add the -DOE_OPENSSL_SUPPRESS_UNSUPPORTED option when compiling the program."
// clang-format on

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
 * are recommended not to use inside an enclave.
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

/*
**==============================================================================
**
** <openssl/ssl.h>
**
**==============================================================================
*/

/*
 * The following APIs allow users to configure an OpenSSL application to look up
 * certificates from the host filesystem, which is not trusted in OE's
 * threat model, and therefore are recommended not to use inside an enclave.
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
**==============================================================================
**
** <openssl/x509_vfy.h>
**
**==============================================================================
*/

/*
 * The following APIs allow users to configure an OpenSSL application to look up
 * certificates from the host filesystem, which is not trusted in OE's
 * threat model, and therefore are recommended not to use inside an enclave.
 */

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_load_cert_file(X509_LOOKUP* ctx, const char* file, int type);
#define X509_load_cert_file OE_OPENSSL_RAISE_ERROR(X509_load_cert_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_load_crl_file(X509_LOOKUP* ctx, const char* file, int type);
#define X509_load_crl_file OE_OPENSSL_RAISE_ERROR(X509_load_crl_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_load_cert_crl_file(X509_LOOKUP* ctx, const char* file, int type);
#define X509_load_cert_crl_file OE_OPENSSL_RAISE_ERROR(X509_load_cert_crl_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
X509_LOOKUP_METHOD* X509_LOOKUP_hash_dir(void);
#define X509_LOOKUP_hash_dir OE_OPENSSL_RAISE_ERROR(X509_LOOKUP_hash_dir)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
X509_LOOKUP_METHOD* X509_LOOKUP_file(void);
#define X509_LOOKUP_file OE_OPENSSL_RAISE_ERROR(X509_LOOKUP_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_locations(
    X509_STORE* ctx,
    const char* file,
    const char* dir);
#define X509_STORE_load_locations \
    OE_OPENSSL_RAISE_ERROR(X509_STORE_load_locations)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_set_default_paths(X509_STORE* ctx);
#define X509_STORE_set_default_paths \
    OE_OPENSSL_RAISE_ERRO(X509_STORE_set_default_paths)

OE_OPENSSL_EXTERN_C_END

#endif /* !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED) */
#endif /* _OE_OPENSSL_UNSUPPORTED_H */
