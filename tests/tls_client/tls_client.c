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

#include "tls_client.h"

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

    /* ATTN: empty verify for now */

    *flags = 0;

    return 0;
}

static int _load_file(const char* path, uint8_t** data_out, size_t* size_out)
{
    int result = -1;
    FILE* is = NULL;
    uint8_t* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    /* Check parameters */
    if (!path || !data_out || !size_out)
        goto done;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        size = (size_t)st.st_size;
    }

    /* Allocate memory to hold contents of file */
    if (!(data = calloc(1, size + 1)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    *data_out = data;
    data = NULL;
    *size_out = size;

    result = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return result;
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
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    int retval;
    uint8_t* cert_data = NULL;
    size_t cert_size;
    uint8_t* private_key_data = NULL;
    size_t private_key_size;

    tls_clear_error(error);

    /* Load the attested certificate */
    if (_load_file(CERT_PATH, &cert_data, &cert_size) != 0)
    {
        tls_set_error(error, "failed to load file", CERT_PATH);
        goto done;
    }

    /* Parse the certificate */
    if ((retval = mbedtls_x509_crt_parse_der(crt, cert_data, cert_size)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_x509_crt_parse_der");
        goto done;
    }

    /* Load the attested certificate */
    if (_load_file(PRIVATE_KEY_PATH, &private_key_data, &private_key_size) != 0)
    {
        tls_set_error(error, "failed to load file", PRIVATE_KEY_PATH);
        goto done;
    }

    /* Parse the private key */
    if ((retval = mbedtls_pk_parse_key(
             pk, private_key_data, private_key_size + 1, NULL, 0)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_pk_parse_key");
        goto done;
    }

    ret = 0;

done:

    if (cert_data)
        free(cert_data);

    if (private_key_data)
        free(private_key_data);

    return ret;
}

static int _configure_client_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    int retval;

    tls_clear_error(error);

    if (_load_cert_and_private_key(crt, pk, error) != 0)
    {
        goto done;
    }

    if ((retval = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ssl_config_defaults");
        goto done;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(conf, _mbedtls_dbg, stdout);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, _cert_verify_callback, NULL);

    /* Set own certificate chain and private key */
    if ((retval = mbedtls_ssl_conf_own_cert(conf, crt, pk)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ssl_conf_own_cert");
        goto done;
    }

    if ((retval = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ssl_setup");
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int tls_client_connect(
    const char* server_name,
    const char* server_port,
    tls_client_t** client_out,
    tls_error_t* error)
{
    int ret = -1;
    int retval;
    tls_client_t* client = NULL;
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
        if (!(client = calloc(1, sizeof(tls_client_t))))
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

    if ((retval = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_entropy_func()");
        goto done;
    }

    if ((retval = mbedtls_net_connect(
             &client->net, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) !=
        0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_net_connect()");
        goto done;
    }

    if (_configure_client_ssl(
            &client->ssl, &conf, &ctr_drbg, &crt, &pk, error) != 0)
    {
        goto done;
    }

    if ((retval = mbedtls_ssl_set_hostname(&client->ssl, server_name)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ssl_set_hostname");
        goto done;
    }

    mbedtls_ssl_set_bio(
        &client->ssl, &client->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((retval = mbedtls_ssl_handshake(&client->ssl)) != 0)
    {
        if (retval != MBEDTLS_ERR_SSL_WANT_READ &&
            retval != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            tls_set_mbedtls_error(error, retval, "mbedtls_ssl_handshake");
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

    return ret;
}

int tls_client_write(
    tls_client_t* client,
    const void* data,
    size_t size,
    tls_error_t* error)
{
    int ret = -1;
    int retval;

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
        retval = mbedtls_ssl_write(&client->ssl, data, size);

        if (retval == MBEDTLS_ERR_SSL_WANT_READ ||
            retval == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (retval == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || retval == 0)
        {
            /* end of file */
            ret = 0;
            break;
        }

        if (retval < 0)
        {
            tls_set_mbedtls_error(error, retval, "mbedtls_ssl_write");
            goto done;
        }

        ret = retval;
        break;
    }

done:

    return ret;
}

int tls_client_read(
    tls_client_t* client,
    void* data,
    size_t size,
    tls_error_t* error)
{
    int ret = -1;
    int retval;

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
        retval = mbedtls_ssl_read(&client->ssl, data, size);

        if (retval == MBEDTLS_ERR_SSL_WANT_READ ||
            retval == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (retval == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || retval == 0)
        {
            /* end of file */
            ret = 0;
            break;
        }

        if (retval < 0)
        {
            tls_set_mbedtls_error(error, retval, "mbedtls_ssl_read");
            goto done;
        }

        /* Save number of bytes read */
        ret = retval;
        break;
    }

done:

    return ret;
}

int tls_client_close(tls_client_t* client)
{
    (void)client;
#if 0
    mbedtls_ssl_close_notify(&client->ssl);
#endif
    return -1;
}
