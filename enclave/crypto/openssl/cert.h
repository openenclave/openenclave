// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_OPENSSL_CERT_H
#define _OE_ENCLAVE_CRYPTO_OPENSSL_CERT_H

#include <openssl/x509.h>

/* The value is based on the implementation of Mbed TLS
 * (MBEDTLS_X509_MAX_DN_NAME_SIZE). */
#define OE_X509_MAX_NAME_SIZE 256

X509_NAME* X509_parse_name(const char* name_string);

#endif /* _OE_ENCLAVE_CRYPTO_OPENSSL_CERT_H */
