#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl_cache.h>

#include "tls_client.h"

#define DEBUG_LEVEL 1

const char CERT_PATH[] = "/tmp/oe_attested_cert.der";
const char PRIVATE_KEY_PATH[] = "/tmp/oe_private_key.pem";

static void _clear_error(tls_error_t* error)
{
    if (error)
    {
        error->code = 0;
        error->message[0] = '\0';
        error->detail[0] = '\0';
    }
}

static void _set_mbedtls_error(tls_error_t* error, int code, const char* detail)
{
    _clear_error(error);

    if (error && code)
    {
        error->code = code;

        if (detail)
        {
            memcpy(error->detail, detail, sizeof(error->detail));
            error->detail[sizeof(error->detail)-1] = '\0';
        }

        mbedtls_strerror(code, error->message, sizeof(error->message));
    }
}

static void _set_error(
    tls_error_t* error,
    const char* message,
    const char* detail)
{
    _clear_error(error);

    if (error)
    {
        error->code = -1;

        if (message)
        {
            memcpy(error->message, message, sizeof(error->message));
            error->message[sizeof(error->message)-1] = '\0';
        }

        if (detail)
        {
            memcpy(error->detail, detail, sizeof(error->detail));
            error->detail[sizeof(error->detail)-1] = '\0';
        }
    }
}

void tls_dump_error(const tls_error_t* error)
{
    printf("error: %d: %s: %s\n", error->code, error->message, error->detail);
}

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
    if (!(data = malloc(size)))
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

    printf("_mbedtls_dbg: %s:%04d: %s", file, line, str);
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

    _clear_error(error);

    /* Load the attested certificate */
    if (_load_file(CERT_PATH, &cert_data, &cert_size) != 0)
    {
        _set_error(error, "failed to load file", CERT_PATH);
        goto done;
    }

    /* Parse the certificate */
    if ((retval = mbedtls_x509_crt_parse_der(crt, cert_data, cert_size)) != 0)
    {
        _set_mbedtls_error(error, retval, "mbedtls_x509_crt_parse_der");
        goto done;
    }

    /* Load the attested certificate */
    if (_load_file(PRIVATE_KEY_PATH, &private_key_data, &private_key_size) != 0)
    {
        _set_error(error, "failed to load file", PRIVATE_KEY_PATH);
        goto done;
    }

    /* Parse the private key */
    if ((retval = mbedtls_pk_parse_key(
        pk, private_key_data, private_key_size, NULL, 0)) != 0)
    {
        _set_mbedtls_error(error, retval, "mbedtls_pk_parse_key");
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

int _configure_client_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    int retval;

    _clear_error(error);

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
        _set_mbedtls_error(error, retval, "mbedtls_ssl_config_defaults");
        goto done;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(conf, _mbedtls_dbg, stdout);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, _cert_verify_callback, NULL);

    /* Set own certificate chain and private key */
    if ((retval = mbedtls_ssl_conf_own_cert(conf, crt, pk)) != 0)
    {
        _set_mbedtls_error(error, retval, "mbedtls_ssl_conf_own_cert");
        goto done;
    }

    if ((retval = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        _set_mbedtls_error(error, retval, "mbedtls_ssl_setup");
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int tls_client_connect(
    char* server_name,
    char* server_port,
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

    _clear_error(error);

    if (client_out)
        *client_out = NULL;

    if (!client_out)
    {
        _set_error(error, "invalid client parameter", NULL);
        goto done;
    }

    if (!server_name)
    {
        _set_error(error, "invalid server_name parameter", NULL);
        goto done;
    }

    if (!server_port)
    {
        _set_error(error, "invalid server_port parameter", NULL);
        goto done;
    }

    /* Initialize the client structure */
    {
        if (!(client = calloc(1, sizeof(tls_client_t))))
        {
            _set_error(error, "calloc() failed", "out of memory");
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
        _set_mbedtls_error(error, retval, "mbedtls_entropy_func()");
        goto done;
    }

    if ((retval = mbedtls_net_connect(
             &client->net,
             server_name, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        _set_mbedtls_error(error, retval, "mbedtls_net_connect()");
        goto done;
    }

    if (_configure_client_ssl(
        &client->ssl, &conf, &ctr_drbg, &crt, &pk, error) != 0)
    {
        goto done;
    }

    if ((retval = mbedtls_ssl_set_hostname(&client->ssl, server_name)) != 0)
    {
        _set_mbedtls_error(error, retval, "mbedtls_ssl_set_hostname");
        goto done;
    }

    mbedtls_ssl_set_bio(
        &client->ssl, &client->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((retval = mbedtls_ssl_handshake(&client->ssl)) != 0)
    {
        if (retval != MBEDTLS_ERR_SSL_WANT_READ &&
            retval != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            _set_mbedtls_error(error, retval, "mbedtls_ssl_handshake");
            goto done;
        }
    }

    if (mbedtls_ssl_get_verify_result(&client->ssl) != 0)
    {
        mbedtls_ssl_close_notify(&client->ssl);
        _set_mbedtls_error(error, 1, "mbedtls_ssl_get_verify_result");
        goto done;
    }

    mbedtls_ssl_close_notify(&client->ssl);

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

    _clear_error(error);

    if (!client)
    {
        _set_error(error, "invalid client parameter", NULL);
        goto done;
    }

    if (!data)
    {
        _set_error(error, "invalid data parameter", NULL);
        goto done;
    }

    if (!size)
    {
        _set_error(error, "invalid size parameter", NULL);
        goto done;
    }

    for (;;)
    {
        retval = mbedtls_ssl_write(&client->ssl, data, size);

        if (retval != MBEDTLS_ERR_SSL_WANT_READ &&
            retval != MBEDTLS_ERR_SSL_WANT_WRITE)
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
            _set_mbedtls_error(error, retval, "mbedtls_ssl_write");
            break;
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

    ret = 0;

    if (!client)
    {
        _set_error(error, "invalid client parameter", NULL);
        goto done;
    }

    if (!data)
    {
        _set_error(error, "invalid data parameter", NULL);
        goto done;
    }

    if (!size)
    {
        _set_error(error, "invalid size parameter", NULL);
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
            _set_mbedtls_error(error, retval, "mbedtls_ssl_read");
            break;
        }

        /* Save number of bytes read */
        ret = retval;
        break;
    }

done:

    return ret;
}
