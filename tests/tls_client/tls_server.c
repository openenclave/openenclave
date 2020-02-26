#define _GNU_SOURCE
//#define INSIDE_ENCLAVE

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

#include "common.h"
#include "gencert.h"
#include "tls_server.h"

#if defined(INSIDE_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#define DEBUG_LEVEL 1

#if !defined(INSIDE_ENCLAVE)
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
#endif /* !defined(INSIDE_ENCLAVE) */

#if !defined(INSIDE_ENCLAVE)
static int _get_cert_and_private_key(
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
#endif /* !defined(INSIDE_ENCLAVE) */

#if defined(INSIDE_ENCLAVE)
static int _get_cert_and_private_key(
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    oe_result_t retval;
    uint8_t* cert_data = NULL;
    size_t cert_size;
    uint8_t* private_key_data = NULL;
    size_t private_key_size;

    tls_clear_error(error);

    if (!crt || !pk)
        goto done;

    if ((retval = oe_generate_cert_and_private_key(
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
#endif /* defined(INSIDE_ENCLAVE) */

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

#if defined(INSIDE_ENCLAVE)
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
#endif /* defined(INSIDE_ENCLAVE) */

static int _cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    int ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    oe_result_t retval;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;
    (void)depth;

    *flags = (uint32_t)MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    if (cert_size <= 0)
        goto done;

#if defined(INSIDE_ENCLAVE)
    if ((retval = oe_verify_attestation_certificate(
             cert_buf, cert_size, _enclave_identity_verifier, NULL)) != OE_OK)
    {
        goto done;
    }
#else
    (void)retval;
#endif

    ret = 0;
    *flags = 0;

done:
    return ret;
}

static int _configure_server_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ssl_cache_context* cache,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* crt,
    mbedtls_pk_context* pk,
    tls_error_t* error)
{
    int ret = -1;
    int retval;

    tls_clear_error(error);

    if ((retval = _get_cert_and_private_key(crt, pk, error)) != 0)
    {
        goto done;
    }

    if ((retval = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ssl_config_defaults");
        goto done;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    mbedtls_ssl_conf_dbg(conf, _mbedtls_dbg, stdout);

    mbedtls_ssl_conf_session_cache(
        conf, cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_verify(conf, _cert_verify_callback, NULL);

    mbedtls_ssl_conf_ca_chain(conf, crt->next, NULL);

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

int tls_server_create(
    const char* server_name,
    const char* server_port,
    tls_server_t** server_out,
    tls_error_t* error)
{
    int ret = -1;
    int retval;
    tls_server_t* server = NULL;
    const char* pers = "tls_server";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_cache_context cache;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cache_init(&cache);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    tls_clear_error(error);

#if !defined(NDEBUG)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    if (!server_out)
    {
        tls_set_error(error, "invalid server_out parameter", NULL);
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

    /* Initialize the server structure */
    {
        if (!(server = calloc(1, sizeof(tls_server_t))))
        {
            tls_set_error(error, "calloc() failed", "out of memory");
            goto done;
        }

        mbedtls_net_init(&server->net);
        mbedtls_ssl_init(&server->ssl);
    }

    if ((retval = mbedtls_net_bind(
             &server->net, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) !=
        0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_net_bind");
        goto done;
    }

    if ((retval = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ctr_drbg_seed");
        goto done;
    }

    if ((retval = _configure_server_ssl(
             &server->ssl,
             &conf,
             &cache,
             &ctr_drbg,
             &server_cert,
             &pkey,
             error)) != 0)
    {
        goto done;
    }

    *server_out = server;
    server = NULL;

    ret = 0;

done:

    if (server)
    {
        mbedtls_net_free(&server->net);
        mbedtls_ssl_free(&server->ssl);
        free(server);
    }

    return ret;
}

int tls_server_listen(tls_server_t* server, tls_error_t* error)
{
    int ret = -1;
    int retval;
    mbedtls_net_context net;
    unsigned char buf[1024];
    size_t bytes_read = 0;

    tls_clear_error(error);

    if (!server)
    {
        tls_set_error(error, "invalid server parameter", NULL);
        goto done;
    }

    if ((retval = mbedtls_ssl_session_reset(&server->ssl)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_ssl_session_reset");
        goto done;
    }

    printf("ACCEPT...\n");
    if ((retval = mbedtls_net_accept(&server->net, &net, NULL, 0, NULL)) != 0)
    {
        tls_set_mbedtls_error(error, retval, "mbedtls_net_accept");
        goto done;
    }

    printf("listen=%d accept=%d\n", server->net.fd, net.fd);

    printf("ACCEPTED...\n");
    mbedtls_ssl_set_bio(
        &server->ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf("HANDSHAKE...\n");
    while ((retval = mbedtls_ssl_handshake(&server->ssl)) != 0)
    {
        if (retval != MBEDTLS_ERR_SSL_WANT_READ &&
            retval != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            tls_set_mbedtls_error(error, retval, "mbedtls_ssl_handshake");
            goto done;
        }
    }

    printf("VERIFY...\n");
    if (mbedtls_ssl_get_verify_result(&server->ssl) != 0)
    {
        tls_set_error(error, "verify failed", "mbedtls_ssl_get_verify_result");
        mbedtls_ssl_close_notify(&server->ssl);
        goto done;
    }

    printf("READ...\n");

    for (;;)
    {
        retval = mbedtls_ssl_read(&server->ssl, buf, sizeof(buf));

        if (retval == MBEDTLS_ERR_SSL_WANT_READ ||
            retval == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (retval <= 0)
        {
            switch (retval)
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                {
                    printf("connection was closed gracefully\n");
                    tls_set_mbedtls_error(error, retval, "closed");
                    goto done;
                }

                case MBEDTLS_ERR_NET_CONN_RESET:
                {
                    printf("connection was reset by peer\n");
                    tls_set_mbedtls_error(error, retval, "reset");
                    goto done;
                }

                default:
                {
                    tls_set_mbedtls_error(error, retval, "read failed");
                    goto done;
                }
            }

            break;
        }

        bytes_read = (size_t)retval;
        break;

        printf("server.read.retval=%d\n", retval);
    }

    printf("buf{%s}\n", buf);

    for (;;)
    {
        retval = mbedtls_ssl_write(&server->ssl, buf, bytes_read);

        if (retval == MBEDTLS_ERR_SSL_WANT_READ ||
            retval == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            continue;
        }

        if (retval == MBEDTLS_ERR_NET_CONN_RESET)
        {
            printf("peer closed the connection\n");
            tls_set_mbedtls_error(error, retval, "peer closed");
            goto done;
        }

        if (retval < 0)
        {
            tls_set_mbedtls_error(error, retval, "error");
            goto done;
        }

        printf("write: %d\n", retval);
        break;
    }

    printf("bytes_written=%d\n", retval);

    for (;;)
    {
        retval = mbedtls_ssl_close_notify(&server->ssl);

        if (retval == MBEDTLS_ERR_SSL_WANT_READ ||
            retval == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            goto done;
        }

        if (retval != 0)
        {
            tls_set_mbedtls_error(error, retval, "close notify");
            goto done;
        }

        break;
    }

    ret = 0;
#if 0
    len = ret;
    OE_TRACE_INFO(" %d bytes written\n", len);
    OE_TRACE_INFO("Closing the connection...\n");
    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            OE_TRACE_ERROR(
                "failed! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto waiting_for_connection_request;
        }
    }

    ret = 0;
    // uncomment the following lien if you want this tls server run in loop
    // goto waiting_for_connection_request;
done:
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        OE_TRACE_ERROR("Last error was: %d - %s\n\n", ret, error_buf);
    }

    // free resource
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&server_cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cache_free(&cache);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    // fflush(stdout);

    return (ret);
#endif

done:

    return ret;
}
