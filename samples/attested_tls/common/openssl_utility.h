// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/report.h>
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

oe_result_t load_ssl_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& cert,
    EVP_PKEY*& pkey);