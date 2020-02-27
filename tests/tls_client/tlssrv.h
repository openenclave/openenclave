// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TLSSRV_H
#define _TLSSRV_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>

typedef struct _tlssrv_err
{
    char buf[1024];
} tlssrv_err_t;

void tlssrv_put_err(tlssrv_err_t* err);

typedef struct _tlssrv
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    mbedtls_ssl_cache_context cache;
} tlssrv_t;

int tlssrv_startup(tlssrv_err_t* err);

int tlssrv_shutdown(tlssrv_err_t* err);

int tlssrv_create(
    const char* host,
    const char* port,
    tlssrv_t** srv_out,
    tlssrv_err_t* err);

int tlssrv_destroy(tlssrv_t* srv, tlssrv_err_t* err);

int tlssrv_listen(tlssrv_t* srv, tlssrv_err_t* err);

int tlssrv_read(tlssrv_t* srv, void* data, size_t size, tlssrv_err_t* err);

int tlssrv_write(
    tlssrv_t* srv,
    const void* data,
    size_t size,
    tlssrv_err_t* err);

#endif /* _TLSSRV_H */
