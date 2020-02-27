// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TLSSRV_H
#define _TLSSRV_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include "common.h"

typedef struct _tlssrv
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
} tlssrv_t;

int tlssrv_create(
    const char* server_name,
    const char* server_port,
    tlssrv_t** client_out,
    tls_error_t* error);

int tlssrv_listen(tlssrv_t* server, tls_error_t* error);

int tlssrv_read(tlssrv_t* client, void* data, size_t size, tls_error_t* error);

int tlssrv_write(
    tlssrv_t* client,
    const void* data,
    size_t size,
    tls_error_t* error);

void tls_dump_error(const tls_error_t* error);

#endif /* _TLSSRV_H */
