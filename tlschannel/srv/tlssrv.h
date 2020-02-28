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

typedef oe_result_t (*verify_identity_function_t)(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn);

typedef struct _tlssrv
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    mbedtls_ssl_cache_context cache;
    verify_identity_function_t verify_identity;
    void* verify_identity_arg;
} tlssrv_t;

void tlssrv_put_err(const tlssrv_err_t* err);

int tlssrv_startup(tlssrv_err_t* err);

int tlssrv_shutdown(tlssrv_err_t* err);

int tlssrv_create(
    const char* host,
    const char* port,
    verify_identity_function_t verify_identity,
    void* verify_identity_arg,
    tlssrv_t** srv_out,
    tlssrv_err_t* err);

int tlssrv_destroy(tlssrv_t* srv, tlssrv_err_t* err);

int tlssrv_accept(tlssrv_t* srv, mbedtls_net_context* conn, tlssrv_err_t* err);

int tlssrv_read(tlssrv_t* srv, void* data, size_t size, tlssrv_err_t* err);

int tlssrv_write(
    tlssrv_t* srv,
    const void* data,
    size_t size,
    tlssrv_err_t* err);

#endif /* _TLSSRV_H */
