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

#include "tls_client.h"

#define DEBUG_LEVEL 1

#define TEST_CLI_CRT_EC_DER                                                   \
    {                                                                         \
        0x30, 0x82, 0x01, 0xdf, 0x30, 0x82, 0x01, 0x63, 0xa0, 0x03, 0x02,     \
            0x01, 0x02, 0x02, 0x01, 0x0d, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, \
            0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00, 0x30, 0x3e, 0x31, \
            0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, \
            0x4c, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, \
            0x08, 0x50, 0x6f, 0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x1c, \
            0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x13, 0x50, 0x6f, \
            0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x20, 0x54, 0x65, 0x73, 0x74, \
            0x20, 0x45, 0x43, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, \
            0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, 0x34, 0x34, 0x30, 0x30, \
            0x5a, 0x17, 0x0d, 0x32, 0x39, 0x30, 0x32, 0x31, 0x30, 0x31, 0x34, \
            0x34, 0x34, 0x30, 0x30, 0x5a, 0x30, 0x41, 0x31, 0x0b, 0x30, 0x09, \
            0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4e, 0x4c, 0x31, 0x11, \
            0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x50, 0x6f, \
            0x6c, 0x61, 0x72, 0x53, 0x53, 0x4c, 0x31, 0x1f, 0x30, 0x1d, 0x06, \
            0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x50, 0x6f, 0x6c, 0x61, 0x72, \
            0x53, 0x53, 0x4c, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6c, \
            0x69, 0x65, 0x6e, 0x74, 0x20, 0x32, 0x30, 0x59, 0x30, 0x13, 0x06, \
            0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, \
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, \
            0x57, 0xe5, 0xae, 0xb1, 0x73, 0xdf, 0xd3, 0xac, 0xbb, 0x93, 0xb8, \
            0x81, 0xff, 0x12, 0xae, 0xee, 0xe6, 0x53, 0xac, 0xce, 0x55, 0x53, \
            0xf6, 0x34, 0x0e, 0xcc, 0x2e, 0xe3, 0x63, 0x25, 0x0b, 0xdf, 0x98, \
            0xe2, 0xf3, 0x5c, 0x60, 0x36, 0x96, 0xc0, 0xd5, 0x18, 0x14, 0x70, \
            0xe5, 0x7f, 0x9f, 0xd5, 0x4b, 0x45, 0x18, 0xe5, 0xb0, 0x6c, 0xd5, \
            0x5c, 0xf8, 0x96, 0x8f, 0x87, 0x70, 0xa3, 0xe4, 0xc7, 0xa3, 0x4d, \
            0x30, 0x4b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, \
            0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, \
            0x04, 0x14, 0x7a, 0x00, 0x5f, 0x86, 0x64, 0xfc, 0xe0, 0x5d, 0xe5, \
            0x11, 0x10, 0x3b, 0xb2, 0xe6, 0x3b, 0xc4, 0x26, 0x3f, 0xcf, 0xe2, \
            0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, \
            0x80, 0x14, 0x9d, 0x6d, 0x20, 0x24, 0x49, 0x01, 0x3f, 0x2b, 0xcb, \
            0x78, 0xb5, 0x19, 0xbc, 0x7e, 0x24, 0xc9, 0xdb, 0xfb, 0x36, 0x7c, \
            0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, \
            0x02, 0x05, 0x00, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, \
            0xca, 0xa6, 0x7b, 0x80, 0xca, 0x32, 0x57, 0x54, 0x96, 0x99, 0x43, \
            0x11, 0x3f, 0x50, 0xe8, 0x4a, 0x6d, 0xad, 0xee, 0xee, 0x51, 0x62, \
            0xa1, 0xb0, 0xb3, 0x85, 0xfb, 0x33, 0xe4, 0x28, 0x39, 0x5f, 0xce, \
            0x92, 0x24, 0x25, 0x81, 0x05, 0x81, 0xc9, 0x68, 0x0c, 0x71, 0x98, \
            0xc3, 0xcd, 0x2e, 0x22, 0x02, 0x30, 0x35, 0xfb, 0x72, 0x3d, 0x7b, \
            0x1a, 0x6d, 0x3a, 0x8c, 0x33, 0xb8, 0x84, 0x1e, 0x05, 0x69, 0x5f, \
            0xf1, 0x91, 0xa3, 0x32, 0xa4, 0x95, 0x8f, 0x72, 0x40, 0x8f, 0xf9, \
            0x7a, 0x80, 0x3a, 0x80, 0x65, 0xbb, 0x63, 0xe8, 0xa6, 0xb8, 0x64, \
            0x7f, 0xa1, 0xaa, 0x39, 0xc9, 0x23, 0x9b, 0x6b, 0xd5, 0x64        \
    }

#define TEST_CLI_KEY_EC_PEM                                                \
    "-----BEGIN EC PRIVATE KEY-----\r\n"                                   \
    "MHcCAQEEIPb3hmTxZ3/mZI3vyk7p3U3wBf+WIop6hDhkFzJhmLcqoAoGCCqGSM49\r\n" \
    "AwEHoUQDQgAEV+WusXPf06y7k7iB/xKu7uZTrM5VU/Y0Dswu42MlC9+Y4vNcYDaW\r\n" \
    "wNUYFHDlf5/VS0UY5bBs1Vz4lo+HcKPkxw==\r\n"                             \
    "-----END EC PRIVATE KEY-----\r\n"

static const char _test_cli_key_ec_pem[] = TEST_CLI_KEY_EC_PEM;

static const unsigned char _test_cli_crt_ec_der[] = TEST_CLI_CRT_EC_DER;

static const size_t _test_cli_crt_ec_der_len = sizeof(_test_cli_crt_ec_der);

static const size_t _test_cli_key_ec_pem_len = sizeof(_test_cli_key_ec_pem);

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

    printf("_cert_verify_callback()\n");
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

#if 0
    cert_data = (uint8_t*)_test_cli_crt_ec_der;
    cert_size = _test_cli_crt_ec_der_len;
#else
    (void)_test_cli_crt_ec_der;
    (void)_test_cli_crt_ec_der_len;
#endif

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

#if 0
    private_key_data = (uint8_t*)_test_cli_key_ec_pem;
    private_key_size = _test_cli_key_ec_pem_len;
#else
    (void)_test_cli_key_ec_pem;
    (void)_test_cli_key_ec_pem_len;
#endif

    /* Parse the private key */
    if ((retval = mbedtls_pk_parse_key(
             pk, private_key_data, private_key_size, NULL, 0)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_pk_parse_key");
        goto done;
    }

    ret = 0;

done:

#if 1
    if (cert_data)
        free(cert_data);

    if (private_key_data)
        free(private_key_data);
#endif

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

#if 0
        if (retval == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || retval == 0)
        {
            /* end of file */
            ret = 0;
            break;
        }
#endif

        if (retval <= 0)
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
        printf("BEFORE.READ: data=%p size=%zu\n", data, size);
        memset(data, 0, size);
        retval = mbedtls_ssl_read(&client->ssl, data, size);
        printf("AFTER.READ: retval=%d\n", retval);

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
