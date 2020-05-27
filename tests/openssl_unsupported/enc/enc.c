// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "openssl_unsupported_t.h"

void test()
{
#ifdef OE_OPENSSL_INIT_LOAD_CONFIG
    unsigned long val = OPENSSL_INIT_LOAD_CONFIG;
    oe_host_printf("val: %lu\n", val);
#endif

#ifdef OE_SSL_CTX_SET_DEFAULT_VERIFY_PATHS
    SSL_CTX_set_default_verify_paths(NULL);
#endif

#ifdef OE_SSL_CTX_SET_DEFAULT_VERIFY_DIR
    SSL_CTX_set_default_verify_dir(NULL);
#endif

#ifdef OE_SSL_CTX_SET_DEFAULT_VERIFY_FILE
    SSL_CTX_set_default_verify_file(NULL);
#endif

#ifdef OE_SSL_CTX_LOAD_VERIFY_LOCATIONS
    SSL_CTX_load_verify_locations(NULL, NULL, NULL);
#endif

#ifdef OE_X509_LOAD_CERT_FILE
    X509_load_cert_file(NULL, NULL, 0);
#endif

#ifdef OE_X509_LOAD_CRL_FILE
    X509_load_crl_file(NULL, NULL, 0);
#endif

#ifdef OE_X509_LOAD_CERT_CRL_FILE
    X509_load_cert_crl_file(NULL, NULL, 0);
#endif

#ifdef OE_X509_LOOKUP_HASH_DIR
    X509_LOOKUP_hash_dir();
#endif

#ifdef OE_X509_LOOKUP_FILE
    X509_LOOKUP_file();
#endif

#ifdef OE_X509_STORE_LOAD_LOCATIONS
    X509_STORE_load_locations(NULL, NULL, NULL);
#endif

#ifdef OE_X509_STORE_SET_DEFAULT_PATHS
    X509_STORE_set_default_paths(NULL);
#endif
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
