// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/platform.h>
// clang-format on

#include <openenclave/internal/print.h>

oe_result_t generate_certificate_and_pkey(
    mbedtls_x509_crt* cert,
    mbedtls_pk_context* private_key);
int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags);
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg);

bool verify_mrsigner(
    char* siging_public_key_buf,
    size_t siging_public_key_buf_size,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size);

// mbedtls debug levels: 0 No debug, 1 Error, 2 State change, 3 Informational, 4
// Verbose
#define DEBUG_LEVEL 1

#define CLIENT_REQUEST_PAYLOAD_SIZE 18

#define CLIENT_GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define SERVER_HTTP_RESPONSE                             \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"         \
    "A message from TLS server inside enclave\r\n"

#define SERVER_RESPONSE_PAYLOAD_SIZE 194