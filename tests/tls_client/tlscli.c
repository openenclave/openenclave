// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>

#include "tlscli.h"

#define DEBUG_LEVEL 1

static int _cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    (void)data;
    (void)crt;
    (void)depth;
    (void)flags;

    *flags = 0;

    return 0;
}

/* The mbedtls debug tracing function */
static void _mbedtls_dbg(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    (void)level;
    (void)ctx;

    printf("_mbedtls_dbg.cli: %s:%04d: %s", file, line, str);
}

static int _load_cert_and_private_key(
    const char* crt_path,
    const char* pk_path,
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    int r;

    tls_clear_error(error);

    if ((r = mbedtls_x509_crt_parse_file(crt, crt_path) != 0))
    {
        tls_set_mbedtls_error(error, r, crt_path);
        goto done;
    }

    if ((r = mbedtls_pk_parse_keyfile(pk, pk_path, "")) != 0)
    {
        tls_set_mbedtls_error(error, r, pk_path);
        goto done;
    }

    ret = 0;

done:

    return ret;
}

static int _configure_client_ssl(
    bool debug,
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ctr_drbg_context* ctr_drbg,
    const char* crt_path,
    const char* pk_path,
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    int r;

    tls_clear_error(error);

    if (_load_cert_and_private_key(crt_path, pk_path, crt, pk, error) != 0)
    {
        goto done;
    }

    if ((r = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_ssl_config_defaults");
        goto done;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    if (debug)
        mbedtls_ssl_conf_dbg(conf, _mbedtls_dbg, stdout);

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, _cert_verify_callback, NULL);

    if ((r = mbedtls_ssl_conf_own_cert(conf, crt, pk)) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_ssl_conf_own_cert");
        goto done;
    }

    if ((r = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_ssl_setup");
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static bool _started;
static const char* _pers = "ssl_client";
static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;

int tlscli_startup(tls_error_t* error)
{
    int ret = -1;
    int r;

    tls_clear_error(error);

    if (_started)
    {
        tls_set_error(error, __FUNCTION__, "already started");
        goto done;
    }

    mbedtls_entropy_init(&_entropy);
    mbedtls_ctr_drbg_init(&_ctr_drbg);

#if !defined(NDEBUG)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if ((r = mbedtls_ctr_drbg_seed(
             &_ctr_drbg,
             mbedtls_entropy_func,
             &_entropy,
             (const unsigned char*)_pers,
             strlen(_pers))) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_entropy_func()");
        goto done;
    }

    _started = true;
    ret = 0;

done:

    if (ret != 0)
    {
        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
    }

    return ret;
}

int tlscli_shutdown(tls_error_t* error)
{
    int ret = -1;

    tls_clear_error(error);

    if (!_started)
    {
        tls_set_error(error, __FUNCTION__, "not started");
        goto done;
    }

    mbedtls_entropy_free(&_entropy);
    mbedtls_ctr_drbg_free(&_ctr_drbg);

done:

    return ret;
}

int tlscli_connect(
    bool debug,
    const char* host,
    const char* port,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** cli_out,
    tls_error_t* error)
{
    int ret = -1;
    int r;
    tlscli_t* cli = NULL;

    tls_clear_error(error);

    if (cli_out)
        *cli_out = NULL;

    if (!_started)
    {
        tls_set_error(error, "not started: please call tlscli_startup()", NULL);
        goto done;
    }

    if (!cli_out)
    {
        tls_set_error(error, "invalid cli parameter", NULL);
        goto done;
    }

    if (!host)
    {
        tls_set_error(error, "invalid host parameter", NULL);
        goto done;
    }

    if (!port)
    {
        tls_set_error(error, "invalid port parameter", NULL);
        goto done;
    }

    /* Initialize the cli structure */
    {
        if (!(cli = calloc(1, sizeof(tlscli_t))))
        {
            tls_set_error(error, "calloc() failed", "out of memory");
            goto done;
        }

        mbedtls_net_init(&cli->net);
        mbedtls_ssl_init(&cli->ssl);
        mbedtls_ssl_config_init(&cli->conf);
        mbedtls_x509_crt_init(&cli->crt);
        mbedtls_pk_init(&cli->pk);
    }

    if ((r = mbedtls_net_connect(
             &cli->net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_net_connect()");
        goto done;
    }

    if (_configure_client_ssl(
            debug,
            &cli->ssl,
            &cli->conf,
            &_ctr_drbg,
            crt_path,
            pk_path,
            &cli->crt,
            &cli->pk,
            error) != 0)
    {
        goto done;
    }

    if ((r = mbedtls_ssl_set_hostname(&cli->ssl, host)) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_ssl_set_hostname");
        goto done;
    }

    mbedtls_ssl_set_bio(
        &cli->ssl, &cli->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((r = mbedtls_ssl_handshake(&cli->ssl)) != 0)
    {
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            tls_set_mbedtls_error(error, r, "mbedtls_ssl_handshake");
            goto done;
        }
    }

    if (mbedtls_ssl_get_verify_result(&cli->ssl) != 0)
    {
        mbedtls_ssl_close_notify(&cli->ssl);
        tls_set_error(
            error, "handshake failed", "mbedtls_ssl_get_verify_result");
        goto done;
    }

    *cli_out = cli;
    cli = NULL;

    ret = 0;

done:

    if (cli)
    {
        mbedtls_ssl_free(&cli->ssl);
        mbedtls_net_free(&cli->net);
        mbedtls_ssl_config_free(&cli->conf);
        mbedtls_x509_crt_free(&cli->crt);
        mbedtls_pk_free(&cli->pk);
        free(cli);
    }

    return ret;
}

int tlscli_write(
    tlscli_t* cli,
    const void* data,
    size_t size,
    tls_error_t* error)
{
    int ret = -1;
    int r;

    tls_clear_error(error);

    if (!cli)
    {
        tls_set_error(error, "invalid cli parameter", NULL);
        goto done;
    }

    if (!data)
    {
        tls_set_error(error, "invalid data parameter", NULL);
        goto done;
    }

    if (!size)
    {
        tls_set_error(error, "invalid size parameter", NULL);
        goto done;
    }

    for (;;)
    {
        r = mbedtls_ssl_write(&cli->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
            tls_set_mbedtls_error(error, r, "mbedtls_ssl_write");
            break;
        }

        if (r <= 0)
        {
            tls_set_mbedtls_error(error, r, "mbedtls_ssl_write");
            goto done;
        }

        ret = r;
        break;
    }

done:

    return ret;
}

int tlscli_read(tlscli_t* cli, void* data, size_t size, tls_error_t* error)
{
    int ret = -1;
    int r;

    if (!cli)
    {
        tls_set_error(error, "invalid cli parameter", NULL);
        goto done;
    }

    if (!data)
    {
        tls_set_error(error, "invalid data parameter", NULL);
        goto done;
    }

    if (!size)
    {
        tls_set_error(error, "invalid size parameter", NULL);
        goto done;
    }

    for (;;)
    {
        memset(data, 0, size);
        r = mbedtls_ssl_read(&cli->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == 0)
        {
            /* end of file */
            ret = 0;
            break;
        }

        if (r < 0)
        {
            tls_set_mbedtls_error(error, r, "mbedtls_ssl_read");
            goto done;
        }

        /* Save number of bytes read */
        ret = r;
        break;
    }

done:

    return ret;
}

int tlscli_disconnect(tlscli_t* cli, tls_error_t* error)
{
    int ret = -1;

    if (!cli)
    {
        tls_set_error(error, "invalid cli parameter", NULL);
        goto done;
    }

    mbedtls_ssl_close_notify(&cli->ssl);

    mbedtls_ssl_free(&cli->ssl);
    mbedtls_net_free(&cli->net);
    mbedtls_ssl_config_free(&cli->conf);
    mbedtls_x509_crt_free(&cli->crt);
    mbedtls_pk_free(&cli->pk);

done:
    return ret;
}
