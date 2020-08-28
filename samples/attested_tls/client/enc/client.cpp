// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <openenclave/enclave.h>
#include <string.h>
#include "../../common/utility.h"

extern "C"
{
    int launch_tls_client(char* server_name, char* server_port);
};

#define MAX_ERROR_BUFF_SIZE 256
char error_buf[MAX_ERROR_BUFF_SIZE];
unsigned char buf[1024];

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags);

static void my_debug(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

int configure_client_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* private_key)
{
    int ret = 1;
    oe_result_t result = OE_FAILURE;

    printf(TLS_CLIENT "Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(client_cert, private_key);
    if (result != OE_OK)
    {
        printf(TLS_CLIENT "failed with %s\n", oe_result_str(result));
        ret = 1;
        goto exit;
    }

    printf(TLS_CLIENT "Setting up the SSL/TLS structure...\n");

    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(
            TLS_CLIENT "failed! mbedtls_ssl_config_defaults returned %d\n",
            ret);
        goto exit;
    }

    printf(TLS_CLIENT "mbedtls_ssl_config_defaults returned successfully\n");

    // set up random engine
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    // set debug function
    mbedtls_ssl_conf_dbg(conf, my_debug, stdout);

    // Set the certificate verification mode to MBEDTLS_SSL_VERIFY_OPTIONAL
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, cert_verify_callback, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(conf, client_cert, private_key)) != 0)
    {
        printf(
            TLS_CLIENT "failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n",
            ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        printf(TLS_CLIENT "failed! mbedtls_ssl_setup returned %d\n", ret);
        goto exit;
    }

    ret = 0;

exit:
    fflush(stdout);
    return ret;
}

int handle_communication_until_done(mbedtls_ssl_context* ssl)
{
    int len = 0;
    int ret = 0;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    // Write client payload to the server
    printf(TLS_CLIENT "-----> Write to server:\n");
    len = sprintf((char*)buf, CLIENT_PAYLOAD);
    while ((ret = mbedtls_ssl_write(ssl, buf, (size_t)len)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(TLS_CLIENT "Failed! mbedtls_ssl_write returned %d\n", ret);
            goto done;
        }
    }

    len = ret;
    printf(TLS_CLIENT "%d bytes written:\n[%s]\n", len, (char*)buf);

    printf(TLS_CLIENT "Read the response from server:\n");
    printf(TLS_CLIENT "<---- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(ssl, buf, (size_t)len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (ret < 0)
        {
            printf(TLS_CLIENT "Failed! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0)
        {
            printf(TLS_CLIENT "\n\nEOF\n\n");
            break;
        }
        len = ret;
        printf(TLS_CLIENT "%d bytes received from server:\n\n", len);
        if (((size_t)len != SERVER_PAYLOAD_SIZE) ||
            (memcmp(SERVER_PAYLOAD, buf, (size_t)len) != 0))
        {
            printf(
                TLS_CLIENT
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                (int)SERVER_PAYLOAD_SIZE,
                len);
            exit_code = MBEDTLS_EXIT_FAILURE;
            goto done;
        }
        else
        {
            printf(TLS_CLIENT "Client done reading server data\n");
            break;
        }
        printf(TLS_CLIENT
               "Verified: the contents of server payload were expected\n\n");
    } while (1);

    ret = 0;
done:
    return ret;
}

int launch_tls_client(char* server_name, char* server_port)
{
    int ret = 1;
    const char* pers = "ssl_client";
    oe_result_t result = OE_FAILURE;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context pkey;

    // Explicitly enabling host resolver and socket features
    if ((result = oe_load_module_host_resolver()) != OE_OK)
    {
        printf(
            TLS_CLIENT "oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
    {
        printf(
            TLS_CLIENT "oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // Initialize mbedtls objects
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&pkey);
    oe_verifier_initialize();

#ifdef ADD_TEST_CHECKING
    if (CLIENT_PAYLOAD_SIZE != strlen(CLIENT_PAYLOAD))
    {
        printf(TLS_CLIENT
               "Error: this client's request payload size does not match"
               " what's defined in CLIENT_PAYLOAD_SIZE, please fix it\n");
        exit_code = MBEDTLS_EXIT_FAILURE;
        goto exit;
    }
#endif

    printf(TLS_CLIENT "\nSeeding the random number generator...\n");
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        printf(
            TLS_CLIENT "Failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    //
    // Start the connection
    //
    printf(
        TLS_CLIENT "Connecting to tcp: %s/%s...\n", server_name, server_port);

    if ((ret = mbedtls_net_connect(
             &server_fd, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(
            TLS_CLIENT "Failed\n  ! mbedtls_net_connect returned %d errno=%d\n",
            ret,
            errno);
        exit_code = ret;
        goto exit;
    }

    printf(TLS_CLIENT "Connected to server @%s.%s\n", server_name, server_port);

    //
    // Configure client SSL settings
    //
    ret = configure_client_ssl(&ssl, &conf, &ctr_drbg, &client_cert, &pkey);
    if (ret != 0)
    {
        printf(TLS_CLIENT "Failed! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, server_name)) != 0)
    {
        printf(
            TLS_CLIENT "Failed! mbedtls_ssl_set_hostname returned %d\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(
        &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    //
    // Handshake
    //
    printf(TLS_CLIENT "Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_CLIENT
                "Failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n",
                -ret);
            goto exit;
        }
    }

    printf(TLS_CLIENT "TLS handshake done successfully\n");

    //
    // Start simple communication with the TLS server
    //

    ret = handle_communication_until_done(&ssl);
    if (ret != 0)
    {
        printf(TLS_CLIENT "client communication error %d\n", ret);
        goto exit;
    }

    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
exit:
    if (exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf(TLS_CLIENT "Last error was: %d - %s\n", ret, error_buf);
    }

    mbedtls_net_free(&server_fd);

    // free mbedtls objects
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    oe_verifier_shutdown();

    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        ret = 0;

    fflush(stdout);
    return (exit_code);
}
