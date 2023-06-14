// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_OPENSSL_X509_VFY_UNSUPPORTED_H
#define _OE_OPENSSL_X509_VFY_UNSUPPORTED_H

#if !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED)

#include <openssl/unsupported.h>

OE_OPENSSL_EXTERN_C_BEGIN

/*
**==============================================================================
**
** <openssl/x509_vfy.h>
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
    OE_OPENSSL_RAISE_ERROR(X509_STORE_set_default_paths)

/*
 * The following OpenSSL 3.0+ APIs allow users to configure an OpenSSL
 * application to look up certificates from the host filesystem or URL store,
 * which is not trusted in OE's threat model, and recommended not to use inside
 * an enclave.
 */

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_load_cert_file_ex(
    X509_LOOKUP* ctx,
    const char* file,
    int type,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_load_cert_file_ex OE_OPENSSL_RAISE_ERROR(X509_load_cert_file_ex)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_load_cert_crl_file_ex(
    X509_LOOKUP* ctx,
    const char* file,
    int type,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_load_cert_crl_file_ex \
    OE_OPENSSL_RAISE_ERROR(X509_load_cert_crl_file_ex)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
X509_LOOKUP_METHOD* X509_LOOKUP_store(void);
#define X509_LOOKUP_store OE_OPENSSL_RAISE_ERROR(X509_LOOKUP_store)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_set_default_paths_ex(
    X509_STORE* ctx,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_STORE_set_default_paths_ex \
    OE_OPENSSL_RAISE_ERRO(X509_STORE_set_default_paths_ex)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_file_ex(
    X509_STORE* ctx,
    const char* file,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_STORE_load_file_ex OE_OPENSSL_RAISE_ERROR(X509_STORE_load_file_ex)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_file(X509_STORE* ctx, const char* file);
#define X509_STORE_load_file OE_OPENSSL_RAISE_ERROR(X509_STORE_load_file)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_path(X509_STORE* ctx, const char* dir);
#define X509_STORE_load_path OE_OPENSSL_RAISE_ERROR(X509_STORE_load_path)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_store_ex(
    X509_STORE* ctx,
    const char* uri,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_STORE_load_store_ex \
    OE_OPENSSL_RAISE_ERROR(X509_STORE_load_store_ex)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_store(X509_STORE* ctx, const char* uri);
#define X509_STORE_load_store OE_OPENSSL_RAISE_ERROR(X509_STORE_load_store)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_STORE_load_locations_ex(
    X509_STORE* ctx,
    const char* file,
    const char* dir,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_STORE_load_locations_ex \
    OE_OPENSSL_RAISE_ERRO(X509_STORE_load_locations_ex)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_LOOKUP_ctrl(
    X509_LOOKUP* ctx,
    int cmd,
    const char* argc,
    long argl,
    char** ret);
#define X509_LOOKUP_ctrl OE_OPENSSL_RAISE_ERROR(X509_LOOKUP_ctrl)

OE_OPENSSL_UNSUPPORTED(OE_UNSUPPORTED_ENCLAVE_OPENSSL_FUNCTION)
int X509_LOOKUP_ctrl_ex(
    X509_LOOKUP* ctx,
    int cmd,
    const char* argc,
    long argl,
    char** ret,
    OSSL_LIB_CTX* libctx,
    const char* propq);
#define X509_LOOKUP_ctrl_ex OE_OPENSSL_RAISE_ERROR(X509_LOOKUP_ctrl_ex)

OE_OPENSSL_EXTERN_C_END

#endif /* !defined(OE_OPENSSL_SUPPRESS_UNSUPPORTED) */
#endif /* _OE_OPENSSL_X509_VFY_UNSUPPORTED_H */
