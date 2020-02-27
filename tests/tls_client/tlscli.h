// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TLSCLI_H
#define _TLSCLI_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include "common.h"

typedef struct _tlscli
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
} tlscli_t;

int tlscli_connect(
    bool debug,
    const char* server_name,
    const char* server_port,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** client_out,
    tls_error_t* error);

int tlscli_disconnect(tlscli_t* client);

int tlscli_read(tlscli_t* client, void* data, size_t size, tls_error_t* error);

int tlscli_write(
    tlscli_t* client,
    const void* data,
    size_t size,
    tls_error_t* error);

#endif /* _TLSCLI_H */
