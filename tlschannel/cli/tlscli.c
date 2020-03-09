// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <openenclave/enclave.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <mbedtls/certs.h>
#include <mbedtls/cmac.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>

#include "tlscli.h"

#define DEBUG_LEVEL 1

static bool _started;
static const char* _pers = "ssl_client";
static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;

static void _clear_err(tlscli_err_t* err)
{
    if (err)
        err->buf[0] = '\0';
}

__attribute__((format(printf, 2, 3))) static void _put_err(
    tlscli_err_t* err,
    const char* fmt,
    ...)
{
    if (err)
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err->buf, sizeof(err->buf), fmt, ap);
        va_end(ap);
    }
}

__attribute__((format(printf, 3, 4))) void _put_mbedtls_err(
    tlscli_err_t* err,
    int code,
    const char* fmt,
    ...)
{
    _clear_err(err);

    if (err && code)
    {
        char buf1[1024];
        mbedtls_strerror(code, buf1, sizeof(buf1));

        char buf2[1024];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf2, sizeof(buf2), fmt, ap);
        va_end(ap);

        snprintf(err->buf, sizeof(err->buf), "%s: %s", buf1, buf2);
    }
}

int tlscli_startup(tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (_started)
    {
        _put_err(err, "already initialized");
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
        _put_mbedtls_err(err, r, "mbedtls_entropy_func()");
        ret = r;
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

int tlscli_shutdown(tlscli_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!_started)
    {
        _put_err(err, "not started");
        goto done;
    }

    mbedtls_entropy_free(&_entropy);
    mbedtls_ctr_drbg_free(&_ctr_drbg);

done:

    return ret;
}

static oe_result_t _enclave_identity_verifier(
    oe_identity_t* identity,
    void* arg)
{
    tlscli_t* cli = (tlscli_t*)arg;

    if (!identity || !cli || !cli->verify_identity)
        return OE_VERIFY_FAILED;

    return cli->verify_identity(
        cli->verify_identity_arg,
        identity->unique_id,
        OE_UNIQUE_ID_SIZE,
        identity->signer_id,
        OE_SIGNER_ID_SIZE,
        identity->product_id,
        OE_PRODUCT_ID_SIZE,
        identity->security_version);
}

static int _cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;
    (void)depth;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    if (cert_size <= 0)
        goto done;

    oe_result_t r;
    if ((r = oe_verify_attestation_certificate(
             cert_buf, cert_size, _enclave_identity_verifier, data)) != OE_OK)
    {
        goto done;
    }

    ret = 0;
    *flags = 0;

done:
    return ret;
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

    printf("_mbedtls_dbg.cli: %s:%u: %s", file, line, str);
}

static int _configure_cli(
    tlscli_t* cli,
    bool debug,
    const char* crt_path,
    const char* pk_path,
    tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if ((r = mbedtls_x509_crt_parse_file(&cli->crt, crt_path) != 0))
    {
        _put_mbedtls_err(err, r, "%s", crt_path);
        ret = r;
        goto done;
    }

    if ((r = mbedtls_pk_parse_keyfile(&cli->pk, pk_path, "")) != 0)
    {
        _put_mbedtls_err(err, r, "%s", pk_path);
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_config_defaults(
             &cli->conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_config_defaults");
        ret = r;
        goto done;
    }

    mbedtls_ssl_conf_rng(&cli->conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

    if (debug)
        mbedtls_ssl_conf_dbg(&cli->conf, _mbedtls_dbg, stdout);

    mbedtls_ssl_conf_authmode(&cli->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&cli->conf, _cert_verify_callback, NULL);

    if ((r = mbedtls_ssl_conf_own_cert(&cli->conf, &cli->crt, &cli->pk)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_conf_own_cert");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_setup(&cli->ssl, &cli->conf)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_setup");
        ret = r;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int tlscli_connect(
    bool debug,
    const char* host,
    const char* port,
    verify_identity_function_t verify_identity,
    void* verify_identity_arg,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** cli_out,
    tlscli_err_t* err)
{
    int ret = -1;
    int r;
    tlscli_t* cli = NULL;

    _clear_err(err);

    if (cli_out)
        *cli_out = NULL;

    if (!_started)
    {
        _put_err(err, "not started: please call tlscli_startup()");
        goto done;
    }

    if (!cli_out)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    if (!host)
    {
        _put_err(err, "invalid host parameter");
        goto done;
    }

    if (!port)
    {
        _put_err(err, "invalid port parameter");
        goto done;
    }

    /* Initialize the cli structure */
    {
        if (!(cli = calloc(1, sizeof(tlscli_t))))
        {
            _put_err(err, "calloc() failed: out of memory");
            goto done;
        }

        cli->verify_identity = verify_identity;
        cli->verify_identity_arg = verify_identity_arg;

        mbedtls_net_init(&cli->net);
        mbedtls_ssl_init(&cli->ssl);
        mbedtls_ssl_config_init(&cli->conf);
        mbedtls_x509_crt_init(&cli->crt);
        mbedtls_pk_init(&cli->pk);
    }

    if ((r = mbedtls_net_connect(
             &cli->net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_net_connect()");
        ret = r;
        goto done;
    }

    if ((r = _configure_cli(cli, debug, crt_path, pk_path, err)) != 0)
    {
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_set_hostname(&cli->ssl, host)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_set_hostname");
        ret = r;
        goto done;
    }

    mbedtls_ssl_set_bio(
        &cli->ssl, &cli->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((r = mbedtls_ssl_handshake(&cli->ssl)) != 0)
    {
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_handshake");
            ret = r;
            goto done;
        }
    }

    if (mbedtls_ssl_get_verify_result(&cli->ssl) != 0)
    {
        mbedtls_ssl_close_notify(&cli->ssl);
        _put_err(err, "handshake failed");
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

int tlscli_read(tlscli_t* cli, void* data, size_t size, tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!cli)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    if (!data)
    {
        _put_err(err, "invalid data parameter");
        goto done;
    }

    if (!size)
    {
        _put_err(err, "invalid size parameter");
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

        if (r <= 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_read");
            ret = r;
            goto done;
        }

        /* Save number of bytes read */
        ret = r;
        break;
    }

done:

    return ret;
}

int tlscli_write(
    tlscli_t* cli,
    const void* data,
    size_t size,
    tlscli_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!cli)
    {
        _put_err(err, "invalid cli parameter");
        goto done;
    }

    if (!data)
    {
        _put_err(err, "invalid data parameter");
        goto done;
    }

    if (!size)
    {
        _put_err(err, "invalid size parameter");
        goto done;
    }

    for (;;)
    {
        r = mbedtls_ssl_write(&cli->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r <= 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_write");
            ret = r;
            goto done;
        }

        ret = r;
        break;
    }

done:

    return ret;
}

int tlscli_destroy(tlscli_t* cli, tlscli_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!cli)
    {
        _put_err(err, "invalid cli parameter");
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

void tlscli_put_err(const tlscli_err_t* err)
{
    if (err)
        fprintf(stderr, "error: %s\n", err->buf);
}
