#ifndef _TLS_SERVER_H
#define _TLS_SERVER_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include "common.h"

typedef struct _tls_server
{
    /* mbedtls_ssl_free() */
    mbedtls_ssl_context ssl;

    /* mbedtls_net_free() */
    mbedtls_net_context net;
} tls_server_t;

int tls_server_create(
    const char* server_name,
    const char* server_port,
    tls_server_t** client_out,
    tls_error_t* error);

int tls_server_listen(tls_server_t* server, tls_error_t* error);

int tls_server_read(
    tls_server_t* client,
    void* data,
    size_t size,
    tls_error_t* error);

int tls_server_write(
    tls_server_t* client,
    const void* data,
    size_t size,
    tls_error_t* error);

void tls_dump_error(const tls_error_t* error);

#endif /* _TLS_SERVER_H */
