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

    printf("_mbedtls_dbg.client: %s:%04d: %s", file, line, str);
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

#if 0
int tlscli_initialize(bool debug)
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
}
#endif

int tlscli_connect(
    bool debug,
    const char* server_name,
    const char* server_port,
    const char* crt_path,
    const char* pk_path,
    tlscli_t** client_out,
    tls_error_t* error)
{
    int ret = -1;
    int r;
    tlscli_t* client = NULL;
    const char* pers = "ssl_client";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&pk);

    tls_clear_error(error);

    if (client_out)
        *client_out = NULL;

    if (!client_out)
    {
        tls_set_error(error, "invalid client parameter", NULL);
        goto done;
    }

    if (!server_name)
    {
        tls_set_error(error, "invalid server_name parameter", NULL);
        goto done;
    }

    if (!server_port)
    {
        tls_set_error(error, "invalid server_port parameter", NULL);
        goto done;
    }

    /* Initialize the client structure */
    {
        if (!(client = calloc(1, sizeof(tlscli_t))))
        {
            tls_set_error(error, "calloc() failed", "out of memory");
            goto done;
        }

        mbedtls_net_init(&client->net);
        mbedtls_ssl_init(&client->ssl);
    }

#if !defined(NDEBUG)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if ((r = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_entropy_func()");
        goto done;
    }

    if ((r = mbedtls_net_connect(
             &client->net, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) !=
        0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_net_connect()");
        goto done;
    }

    if (_configure_client_ssl(
            debug,
            &client->ssl,
            &conf,
            &ctr_drbg,
            crt_path,
            pk_path,
            &crt,
            &pk,
            error) != 0)
    {
        goto done;
    }

    if ((r = mbedtls_ssl_set_hostname(&client->ssl, server_name)) != 0)
    {
        tls_set_mbedtls_error(error, r, "mbedtls_ssl_set_hostname");
        goto done;
    }

    mbedtls_ssl_set_bio(
        &client->ssl, &client->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((r = mbedtls_ssl_handshake(&client->ssl)) != 0)
    {
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            tls_set_mbedtls_error(error, r, "mbedtls_ssl_handshake");
            goto done;
        }
    }

    if (mbedtls_ssl_get_verify_result(&client->ssl) != 0)
    {
        mbedtls_ssl_close_notify(&client->ssl);
        tls_set_error(
            error, "handshake failed", "mbedtls_ssl_get_verify_result");
        goto done;
    }

    *client_out = client;
    client = NULL;

    ret = 0;

done:

#if 0
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pk);

    if (client)
    {
        mbedtls_net_free(&client->net);
        mbedtls_ssl_free(&client->ssl);
        free(client);
    }

    mbedtls_ssl_config_free(&conf);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#endif

    return ret;
}

int tlscli_write(
    tlscli_t* client,
    const void* data,
    size_t size,
    tls_error_t* error)
{
    int ret = -1;
    int r;

    tls_clear_error(error);

    if (!client)
    {
        tls_set_error(error, "invalid client parameter", NULL);
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
        r = mbedtls_ssl_write(&client->ssl, data, size);

        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

#if 0
        if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == 0)
        {
            /* end of file */
            ret = 0;
            break;
        }
#endif

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

int tlscli_read(tlscli_t* client, void* data, size_t size, tls_error_t* error)
{
    int ret = -1;
    int r;

    if (!client)
    {
        tls_set_error(error, "invalid client parameter", NULL);
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
        printf("BEFORE.READ: data=%p size=%zu\n", data, size);
        memset(data, 0, size);
        r = mbedtls_ssl_read(&client->ssl, data, size);
        printf("AFTER.READ: r=%d\n", r);

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

int tlscli_disconnect(tlscli_t* client)
{
    int ret = -1;

    if (!client)
        goto done;

    mbedtls_ssl_close_notify(&client->ssl);

done:
    return ret;
}
