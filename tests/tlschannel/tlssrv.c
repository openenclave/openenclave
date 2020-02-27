// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define _GNU_SOURCE
//#define BUILD_ENCLAVE

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

#include "gencert.h"
#include "tlssrv.h"

#if defined(BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#define DEBUG_LEVEL 1

#define TEST_SRV_CRT_EC_DER                                                   \
    {                                                                         \
        0x30, 0x82, 0x02, 0x1f, 0x30, 0x82, 0x01, 0xa5, 0xa0, 0x03, 0x02,     \
            0x01, 0x02, 0x02, 0x01, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, \
            0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x3e, 0x31, 0x0b, 0x30, \
            0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, \
            0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, \
            0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, \
            0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x50, 0x6f, 0x6c, 0x61, \
            0x72, 0x73, 0x73, 0x6c, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x45, \
            0x43, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x33, 0x30, \
            0x39, 0x32, 0x34, 0x31, 0x35, 0x35, 0x32, 0x30, 0x34, 0x5a, 0x17, \
            0x0d, 0x32, 0x33, 0x30, 0x39, 0x32, 0x32, 0x31, 0x35, 0x35, 0x32, \
            0x30, 0x34, 0x5a, 0x30, 0x34, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, \
            0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, \
            0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61, \
            0x72, 0x53, 0x53, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, \
            0x04, 0x03, 0x13, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, \
            0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, \
            0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, \
            0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x37, 0xcc, 0x56, 0xd9, \
            0x76, 0x09, 0x1e, 0x5a, 0x72, 0x3e, 0xc7, 0x59, 0x2d, 0xff, 0x20, \
            0x6e, 0xee, 0x7c, 0xf9, 0x06, 0x91, 0x74, 0xd0, 0xad, 0x14, 0xb5, \
            0xf7, 0x68, 0x22, 0x59, 0x62, 0x92, 0x4e, 0xe5, 0x00, 0xd8, 0x23, \
            0x11, 0xff, 0xea, 0x2f, 0xd2, 0x34, 0x5d, 0x5d, 0x16, 0xbd, 0x8a, \
            0x88, 0xc2, 0x6b, 0x77, 0x0d, 0x55, 0xcd, 0x8a, 0x2a, 0x0e, 0xfa, \
            0x01, 0xc8, 0xb4, 0xed, 0xff, 0xa3, 0x81, 0x9d, 0x30, 0x81, 0x9a, \
            0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, \
            0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, \
            0x50, 0x61, 0xa5, 0x8f, 0xd4, 0x07, 0xd9, 0xd7, 0x82, 0x01, 0x0c, \
            0xe5, 0x65, 0x7f, 0x8c, 0x63, 0x46, 0xa7, 0x13, 0xbe, 0x30, 0x6e, \
            0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x67, 0x30, 0x65, 0x80, 0x14, \
            0x9d, 0x6d, 0x20, 0x24, 0x49, 0x01, 0x3f, 0x2b, 0xcb, 0x78, 0xb5, \
            0x19, 0xbc, 0x7e, 0x24, 0xc9, 0xdb, 0xfb, 0x36, 0x7c, 0xa1, 0x42, \
            0xa4, 0x40, 0x30, 0x3e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, \
            0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06, \
            0x03, 0x55, 0x04, 0x0a, 0x13, 0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, \
            0x53, 0x53, 0x4c, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, \
            0x03, 0x13, 0x13, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x73, 0x73, 0x6c, \
            0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x20, 0x43, 0x41, \
            0x82, 0x09, 0x00, 0xc1, 0x43, 0xe2, 0x7e, 0x62, 0x43, 0xcc, 0xe8, \
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, \
            0x02, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0x9a, 0x2c, \
            0x5c, 0xd7, 0xa6, 0xdb, 0xa2, 0xe5, 0x64, 0x0d, 0xf0, 0xb9, 0x4e, \
            0xdd, 0xd7, 0x61, 0xd6, 0x13, 0x31, 0xc7, 0xab, 0x73, 0x80, 0xbb, \
            0xd3, 0xd3, 0x73, 0x13, 0x54, 0xad, 0x92, 0x0b, 0x5d, 0xab, 0xd0, \
            0xbc, 0xf7, 0xae, 0x2f, 0xe6, 0xa1, 0x21, 0x29, 0x35, 0x95, 0xaa, \
            0x3e, 0x39, 0x02, 0x30, 0x21, 0x36, 0x7f, 0x9d, 0xc6, 0x5d, 0xc6, \
            0x0b, 0xab, 0x27, 0xf2, 0x25, 0x1d, 0x3b, 0xf1, 0xcf, 0xf1, 0x35, \
            0x25, 0x14, 0xe7, 0xe5, 0xf1, 0x97, 0xb5, 0x59, 0xe3, 0x5e, 0x15, \
            0x7c, 0x66, 0xb9, 0x90, 0x7b, 0xc7, 0x01, 0x10, 0x4f, 0x73, 0xc6, \
            0x00, 0x21, 0x52, 0x2a, 0x0e, 0xf1, 0xc7, 0xd5                    \
    }

#define TEST_SRV_KEY_EC_PEM                                                \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "MHcCAQEEIPEqEyB2AnCoPL/9U/YDHvdqXYbIogTywwyp6/UfDw6noAoGCCqGSM49\r\n" \
    "AwEHoUQDQgAEN8xW2XYJHlpyPsdZLf8gbu58+QaRdNCtFLX3aCJZYpJO5QDYIxH/\r\n" \
    "6i/SNF1dFr2KiMJrdw1VzYoqDvoByLTt/w==\r\n"                             \
    "-----END EC PRIVATE KEY-----\r\n"

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
#if defined(BUILD_ENCLAVE)
{
    int ret = -1;
    oe_result_t r;
    uint8_t* cert_data = NULL;
    size_t cert_size;
    uint8_t* private_key_data = NULL;
    size_t private_key_size;

    _clear_err(err);

    if (!crt || !pk)
        goto done;

    if ((r = oe_generate_cert_and_private_key(
             "CN=Open Enclave SDK,O=OESDK TLS,C=US",
             &cert_data,
             &cert_size,
             &private_key_data,
             &private_key_size)) != OE_OK)
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
#else  /* !defined(BUILD_ENCLAVE) */
{
    int ret = -1;
    int r;
    static const char pk_pem[] = TEST_SRV_KEY_EC_PEM;
    static const unsigned char _crt_der[] = TEST_SRV_CRT_EC_DER;
    static const size_t _crt_der_len = sizeof(_crt_der);
    static const size_t pk_pem_len = sizeof(pk_pem);

    _clear_err(err);

    if ((r = mbedtls_x509_crt_parse_der(crt, _crt_der, _crt_der_len)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_x509_crt_parse_der");
        ret = r;
        goto done;
    }

    if ((r = mbedtls_pk_parse_key(
             pk, (const uint8_t*)pk_pem, pk_pem_len, NULL, 0)) != 0)
    {
        _put_mbedtls_err(err, r, "mbedtls_pk_parse_key");
        ret = r;
        goto done;
    }

    ret = 0;

done:

    return ret;
}
#endif /* defined(BUILD_ENCLAVE) */

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

#if defined(BUILD_ENCLAVE)
static oe_result_t _enclave_identity_verifier(
    oe_identity_t* identity,
    void* arg)
{
    oe_result_t ret = OE_VERIFY_FAILED;

    (void)arg;

#if !defined(NDEBUG)
    /* Dump MRENCLAVE identify */
    {
        printf("identity->unique_id(MRENCLAVE):\n");

        for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
            printf("0x%0x ", (uint8_t)identity->unique_id[i]);

        printf("\n");
    }
#endif

#if !defined(NDEBUG)
    /* Dump MRSIGNER identify */
    {
        printf("identity->signer_id(MRSIGNER):\n");

        for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
            printf("0x%0x ", (uint8_t)identity->signer_id[i]);

        printf("\n");
    }
#endif

    /* ATTN: perform verification of identity here! */

#if !defined(NDEBUG)
    /* Dump MRSIGNER identify */
    {
        printf("identity->product_id :\n");

        for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
            printf("0x%0x ", (uint8_t)identity->product_id[i]);

        printf("\n");
    }
#endif

    ret = OE_OK;

    return ret;
}
#endif /* defined(BUILD_ENCLAVE) */

static int _cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    oe_result_t r;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;
    (void)depth;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    if (cert_size <= 0)
        goto done;

#if defined(BUILD_ENCLAVE)
    if ((r = oe_verify_attestation_certificate(
             cert_buf, cert_size, _enclave_identity_verifier, NULL)) != OE_OK)
    {
        goto done;
    }
#else
    (void)r;
#endif

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

    mbedtls_ssl_conf_verify(&srv->conf, _cert_verify_callback, NULL);

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
    const char* server_name,
    const char* server_port,
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
        _put_err(err, "invalid srv_out parameter", NULL);
        goto done;
    }

    if (!server_name)
    {
        _put_err(err, "invalid server_name parameter", NULL);
        goto done;
    }

    if (!server_port)
    {
        _put_err(err, "invalid server_port parameter", NULL);
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

        mbedtls_net_init(&srv->net);
        mbedtls_ssl_init(&srv->ssl);
        mbedtls_ssl_config_init(&srv->conf);
        mbedtls_ssl_cache_init(&srv->cache);
        mbedtls_x509_crt_init(&srv->crt);
        mbedtls_pk_init(&srv->pk);
    }

    if ((r = mbedtls_net_bind(
             &srv->net, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
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
        _put_err(err, "invalid srv parameter", NULL);
        goto done;
    }

    if (!conn)
    {
        _put_err(err, "invalid conn parameter", NULL);
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
