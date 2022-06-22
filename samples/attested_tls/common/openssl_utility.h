// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
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

oe_result_t load_tls_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& certificate,
    EVP_PKEY*& pkey);

oe_result_t initalize_ssl_context(SSL_CONF_CTX*& ssl_conf_ctx, SSL_CTX*& ctx);
