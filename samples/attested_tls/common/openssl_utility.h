// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/ssl.h>

#define ADD_TEST_CHECKING // checks if expected data is read by the peer

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);
int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length);