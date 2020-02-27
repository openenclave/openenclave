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
    mbedtls_ssl_config conf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
} tlscli_t;

int tlscli_startup(tls_error_t* error);

int tlscli_connect(
    bool debug,
    const char* host,
    const char* port,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** cli_out,
    tls_error_t* error);

int tlscli_disconnect(tlscli_t* cli, tls_error_t* error);

int tlscli_read(tlscli_t* cli, void* data, size_t size, tls_error_t* error);

int tlscli_write(
    tlscli_t* cli,
    const void* data,
    size_t size,
    tls_error_t* error);

#endif /* _TLSCLI_H */
