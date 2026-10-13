// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_CRYPTO_OPENSSL_CERT_H
#define _OE_ENCLAVE_CRYPTO_OPENSSL_CERT_H

#include <openssl/x509.h>

/* Maximum supported X.509 distinguished-name size. */
#define OE_X509_MAX_NAME_SIZE 256

X509_NAME* X509_parse_name(const char* name_string);

#endif /* _OE_ENCLAVE_CRYPTO_OPENSSL_CERT_H */
