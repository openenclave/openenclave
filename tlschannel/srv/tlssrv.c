// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openenclave/enclave.h>

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

#include "../common/gencreds.h"
#include "tlssrv.h"

#define DEBUG_LEVEL 1

static bool _started;
static const char* _pers = "ssl_server";
static mbedtls_entropy_context _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;

static void _clear_err(tlssrv_err_t* err)
{
    if (err)
        err->buf[0] = '\0';
}

__attribute__((format(printf, 2, 3))) static void _put_err(
    tlssrv_err_t* err,
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

__attribute__((format(printf, 3, 4))) static void _put_mbedtls_err(
    tlssrv_err_t* err,
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

int tlssrv_startup(tlssrv_err_t* err)
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

int tlssrv_shutdown(tlssrv_err_t* err)
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

static int _get_cert_and_private_key(
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tlssrv_err_t* err)
{
    int ret = -1;
    uint8_t* cert_data = NULL;
    size_t cert_size;
    uint8_t* private_key_data = NULL;
    size_t private_key_size;
    const char COMMON_NAME[] = "CN=Open Enclave SDK,O=OESDK TLS,C=US";

    _clear_err(err);

    if (!crt || !pk)
        goto done;

    if (oe_generate_attested_credentials(
            COMMON_NAME,
            &cert_data,
            &cert_size,
            &private_key_data,
            &private_key_size) != 0)
    {
        goto done;
    }

    /* Convert the certificate from DER to internal format */
    if (mbedtls_x509_crt_parse_der(crt, cert_data, cert_size) != 0)
    {
        goto done;
    }

    /* Convert the private key from PEM to internal format */
    if (mbedtls_pk_parse_key(pk, private_key_data, private_key_size, NULL, 0) !=
        0)
    {
        goto done;
    }

    ret = 0;

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

    printf("_mbedtls_dbg.server: %s:%04d: %s", file, line, str);
}

static oe_result_t _enclave_identity_verifier(
    oe_identity_t* identity,
    void* arg)
{
    tlssrv_t* srv = (tlssrv_t*)arg;

    if (!identity || !srv || !srv->verify_identity)
        return OE_VERIFY_FAILED;

    return srv->verify_identity(
        srv->verify_identity_arg,
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

static int _configure_srv(tlssrv_t* srv, tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if ((r = _get_cert_and_private_key(&srv->crt, &srv->pk, err)) != 0)
    {
        goto done;
    }

    if ((r = mbedtls_ssl_config_defaults(
             &srv->conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_config_defaults");
        ret = r;
        goto done;
    }

    mbedtls_ssl_conf_rng(&srv->conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

    mbedtls_ssl_conf_dbg(&srv->conf, _mbedtls_dbg, stdout);

    mbedtls_ssl_conf_session_cache(
        &srv->conf, &srv->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    mbedtls_ssl_conf_authmode(&srv->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_verify(&srv->conf, _cert_verify_callback, srv);

    mbedtls_ssl_conf_ca_chain(&srv->conf, srv->crt.next, NULL);

    if ((r = mbedtls_ssl_conf_own_cert(&srv->conf, &srv->crt, &srv->pk)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_conf_own_cert");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ssl_setup(&srv->ssl, &srv->conf)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_setup");
        ret = r;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int tlssrv_create(
    const char* host,
    const char* port,
    verify_identity_function_t verify_identity,
    void* verify_identity_arg,
    tlssrv_t** srv_out,
    tlssrv_err_t* err)
{
    int ret = -1;
    int r;
    tlssrv_t* srv = NULL;
    const char* pers = "tlssrv";

    _clear_err(err);

#if !defined(NDEBUG)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if (!srv_out)
    {
        _put_err(err, "invalid srv_out parameter");
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

    if (!_started)
    {
        _put_err(err, "not started: please call tlssrv_startup");
        goto done;
    }

    /* Initialize the server structure */
    {
        if (!(srv = calloc(1, sizeof(tlssrv_t))))
        {
            _put_err(err, "calloc(): out of memory");
            goto done;
        }

        srv->verify_identity = verify_identity;
        srv->verify_identity_arg = verify_identity_arg;

        mbedtls_net_init(&srv->net);
        mbedtls_ssl_init(&srv->ssl);
        mbedtls_ssl_config_init(&srv->conf);
        mbedtls_ssl_cache_init(&srv->cache);
        mbedtls_x509_crt_init(&srv->crt);
        mbedtls_pk_init(&srv->pk);
    }

    if ((r = mbedtls_net_bind(&srv->net, host, port, MBEDTLS_NET_PROTO_TCP)) !=
        0)
    {
        _put_mbedtls_err(err, r, "mbedtls_net_bind");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_ctr_drbg_seed(
             &_ctr_drbg,
             mbedtls_entropy_func,
             &_entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ctr_drbg_seed");
        ret = r;
        goto done;
    }

    if ((r = _configure_srv(srv, err)) != 0)
    {
        goto done;
    }

    *srv_out = srv;
    srv = NULL;

    ret = 0;

done:

    if (srv)
    {
        mbedtls_net_free(&srv->net);
        mbedtls_ssl_free(&srv->ssl);
        mbedtls_ssl_config_free(&srv->conf);
        mbedtls_x509_crt_free(&srv->crt);
        mbedtls_pk_free(&srv->pk);
        mbedtls_ssl_cache_free(&srv->cache);
        free(srv);
    }

    return ret;
}

int tlssrv_destroy(tlssrv_t* srv, tlssrv_err_t* err)
{
    int ret = -1;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
        goto done;
    }

    mbedtls_ssl_close_notify(&srv->ssl);

    mbedtls_ssl_free(&srv->ssl);
    mbedtls_net_free(&srv->net);
    mbedtls_ssl_config_free(&srv->conf);
    mbedtls_x509_crt_free(&srv->crt);
    mbedtls_pk_free(&srv->pk);

done:
    return ret;
}

int tlssrv_accept(tlssrv_t* srv, mbedtls_net_context* conn, tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
        goto done;
    }

    if (!conn)
    {
        _put_err(err, "invalid conn parameter");
        goto done;
    }

    if ((r = mbedtls_ssl_session_reset(&srv->ssl)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_ssl_session_reset");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_net_accept(&srv->net, conn, NULL, 0, NULL)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_net_accept");
        ret = r;
        goto done;
    }

    mbedtls_ssl_set_bio(
        &srv->ssl, conn, mbedtls_net_send, mbedtls_net_recv, NULL);

    for (;;)
    {
        r = mbedtls_ssl_handshake(&srv->ssl);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (r != 0)
        {
            _put_mbedtls_err(err, r, "mbedtls_ssl_handshake");
            ret = r;
            goto done;
        }

        break;
    }

    if (mbedtls_ssl_get_verify_result(&srv->ssl) != 0)
    {
        _put_err(err, "verify failed");
        mbedtls_ssl_close_notify(&srv->ssl);
        goto done;
    }

    ret = 0;

done:

    return ret;
}

int tlssrv_read(tlssrv_t* srv, void* data, size_t size, tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
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
        r = mbedtls_ssl_read(&srv->ssl, data, size);

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

int tlssrv_write(
    tlssrv_t* srv,
    const void* data,
    size_t size,
    tlssrv_err_t* err)
{
    int ret = -1;
    int r;

    _clear_err(err);

    if (!srv)
    {
        _put_err(err, "invalid srv parameter");
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
        r = mbedtls_ssl_write(&srv->ssl, data, size);

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

void tlssrv_put_err(const tlssrv_err_t* err)
{
    if (err)
        fprintf(stderr, "error: %s\n", err->buf);
}
