// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include "utility.h"

#define TLS_SERVER "OPENSSL_TEST_SERVER: "

oe_result_t generate_certificate_and_pkey(X509*& cert, EVP_PKEY*& pkey);

int cert_verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);

int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);
