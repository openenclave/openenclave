// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TLSCLI_H
#define _TLSCLI_H

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <stdbool.h>

typedef struct _tlscli_err
{
    char buf[1024];
} tlscli_err_t;

void tlscli_put_err(const tlscli_err_t* err);

typedef int (*verify_identity_function_t)(
    void* arg,
    const uint8_t* mrenclave,
    size_t mrenclave_size,
    const uint8_t* mrsigner,
    size_t mrsigner_size,
    const uint8_t* isvprodid,
    size_t isvprodid_size,
    uint64_t isvsvn);

typedef struct _tlscli
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    verify_identity_function_t verify_identity;
    void* verify_identity_arg;
} tlscli_t;

int tlscli_startup(tlscli_err_t* err);

int tlscli_shutdown(tlscli_err_t* err);

int tlscli_connect(
    bool debug,
    const char* host,
    const char* port,
    verify_identity_function_t verify_identity,
    void* verify_identity_arg,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** cli_out,
    tlscli_err_t* err);

int tlscli_destroy(tlscli_t* cli, tlscli_err_t* err);

int tlscli_read(tlscli_t* cli, void* data, size_t size, tlscli_err_t* err);

int tlscli_write(
    tlscli_t* cli,
    const void* data,
    size_t size,
    tlscli_err_t* err);

#endif /* _TLSCLI_H */
