// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include "utility.h"

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);

int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);

int initalize_ssl_context(SSL_CTX*& ctx);

int load_ssl_certificates_and_keys(SSL_CTX* ctx, X509*& cert, EVP_PKEY*& pkey);
