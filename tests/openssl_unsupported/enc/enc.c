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
    // OpenSSL 1.0+ unsupported APIs:

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

    // OpenSSL 3.0+ unsupported APIs:

#ifdef OE_SSL_CTX_SET_DEFAULT_VERIFY_STORE
    SSL_CTX_set_default_verify_store(NULL);
#endif

#ifdef OE_SSL_CTX_LOAD_VERIFY_DIR
    SSL_CTX_load_verify_dir(NULL, NULL);
#endif

#ifdef OE_SSL_CTX_LOAD_VERIFY_FILE
    SSL_CTX_load_verify_file(NULL, NULL);
#endif

#ifdef OE_SSL_CTX_LOAD_VERIFY_STORE
    SSL_CTX_load_verify_store(NULL, NULL);
#endif

#ifdef OE_X509_LOAD_CERT_FILE_EX
    X509_load_cert_file_ex(NULL, NULL, 0, NULL, NULL);
#endif

#ifdef OE_X509_LOAD_CERT_CRL_FILE_EX
    X509_load_cert_crl_file_ex(NULL, NULL, 0, NULL, NULL);
#endif

#ifdef OE_X509_LOOKUP_STORE
    X509_LOOKUP_store();
#endif

#ifdef OE_X509_STORE_LOAD_FILE_EX
    X509_STORE_load_file_ex(NULL, NULL, NULL, NULL);
#endif

#ifdef OE_X509_STORE_LOAD_FILE
    X509_STORE_load_file(NULL, NULL);
#endif

#ifdef OE_X509_STORE_LOAD_PATH
    X509_STORE_load_path(NULL, NULL);
#endif

#ifdef OE_X509_STORE_LOAD_LOCATIONS_EX
    X509_STORE_load_locations_ex(NULL, NULL, NULL, NULL, NULL);
#endif

#ifdef OE_X509_STORE_LOAD_STORE_EX
    X509_STORE_load_store_ex(NULL, NULL, NULL, NULL);
#endif

#ifdef OE_X509_STORE_LOAD_STORE
    X509_STORE_load_store(NULL, NULL);
#endif

#ifdef OE_X509_STORE_SET_DEFAULT_PATHS_EX
    X509_STORE_set_default_paths_ex(NULL);
#endif

#ifdef OE_X509_LOOKUP_CTRL_EX
    X509_LOOKUP_ctrl_ex(NULL, 0, NULL, 0, NULL, NULL, NULL);
#endif

#ifdef OE_X509_LOOKUP_CTRL
    X509_LOOKUP_ctrl(NULL, 0, NULL, 0, NULL);
#endif

#ifdef OE_X509_LOOKUP_LOAD_FILE_EX
    X509_LOOKUP_load_file_ex(NULL, NULL, 0, NULL, NULL);
#endif

#ifdef OE_X509_LOOKUP_LOAD_FILE
    X509_LOOKUP_load_file(NULL, NULL, 0);
#endif

#ifdef OE_X509_LOOKUP_ADD_DIR
    X509_LOOKUP_add_dir(NULL, NULL, 0);
#endif

#ifdef OE_X509_LOOKUP_ADD_STORE_EX
    X509_LOOKUP_add_store_ex(NULL, NULL, NULL, NULL);
#endif

#ifdef OE_X509_LOOKUP_ADD_STORE
    X509_LOOKUP_add_store(NULL, NULL);
#endif

#ifdef OE_X509_LOOKUP_LOAD_STORE_EX
    X509_LOOKUP_load_store_ex(NULL, NULL, NULL, NULL);
#endif

#ifdef OE_X509_LOOKUP_LOAD_STORE
    X509_LOOKUP_load_store(NULL, NULL);
#endif
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
