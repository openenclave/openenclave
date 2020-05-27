// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "../../common/utility.h"

extern "C"
{
    int setup_tls_server(char* server_port, bool keep_server_up);
};

#define MAX_ERROR_BUFF_SIZE 256
char error_buf[MAX_ERROR_BUFF_SIZE];
unsigned char buf[1024];

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags);

#define SERVER_IP "0.0.0.0"

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"         \
    "A message from TLS server inside enclave\r\n"

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

int configure_server_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ssl_cache_context* cache,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* server_cert,
    mbedtls_pk_context* pkey)
{
    int ret = 1;
    oe_result_t result = OE_FAILURE;

    printf(TLS_SERVER "Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(server_cert, pkey);
    if (result != OE_OK)
    {
        printf(TLS_SERVER "failed with %s\n", oe_result_str(result));
        goto exit;
    }

    printf(TLS_SERVER "\nSetting up the SSL configuration....\n");
    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(
            TLS_SERVER
            "failed\n  ! mbedtls_ssl_config_defaults returned failed %d\n",
            ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(conf, my_debug, stdout);
    mbedtls_ssl_conf_session_cache(
        conf, cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    // need to set authmode mode to OPTIONAL for requesting client certificate
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, cert_verify_callback, NULL);
    mbedtls_ssl_conf_ca_chain(conf, server_cert->next, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(conf, server_cert, pkey)) != 0)
    {
        printf(
            TLS_SERVER "failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n",
            ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }
    ret = 0;
exit:
    fflush(stdout);
    return ret;
}

// This routine was created to demonstrate a simple communication scenario
// between a TLS client and an TLS server. In a real TLS server app, you
// definitely will have to do more that just receiving a single message
// from a client.
int handle_communication_until_done(
    mbedtls_ssl_context* ssl,
    mbedtls_net_context* listen_fd,
    mbedtls_net_context* client_fd,
    bool keep_server_up)
{
    int ret = 0;
    int len = 0;

waiting_for_connection_request:

    if (ret != 0 &&
        // ignore EOF errors, which can be caused due to Load Balancers
        // or health checks
        ret != MBEDTLS_ERR_SSL_CONN_EOF)
    {
        mbedtls_strerror(ret, error_buf, MAX_ERROR_BUFF_SIZE);
        printf("Last error was: %d - %s\n", ret, error_buf);
    }

    // reset ssl setup and client_fd to prepare for the new TLS connection
    mbedtls_net_free(client_fd);
    mbedtls_ssl_session_reset(ssl);

    if (ret != MBEDTLS_ERR_SSL_CONN_EOF)
        printf(TLS_SERVER "Waiting for a client connection request...\n");
    if ((ret = mbedtls_net_accept(listen_fd, client_fd, NULL, 0, NULL)) != 0)
    {
        char errbuf[512];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        printf(
            TLS_SERVER " failed\n  ! mbedtls_net_accept returned %d\n %s\n",
            ret,
            errbuf);
        goto done;
    }

    // set up bio callbacks
    mbedtls_ssl_set_bio(
        ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    {
        // Load balancer health-check pings can cause EOF errors
        // Ignore the error, and wait for client to send request
        if (ret == MBEDTLS_ERR_SSL_CONN_EOF)
        {
            goto waiting_for_connection_request;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed\n  ! mbedtls_ssl_handshake returned -0x%x\n",
                -ret);
            goto done;
        }
    }

    printf(TLS_SERVER "mbedtls_ssl_handshake done successfully\n");

    // read client's request
    printf(TLS_SERVER "<---- Read from client:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(ssl, buf, (size_t)len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf(TLS_SERVER "connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    printf(TLS_SERVER "connection was reset by peer\n");
                    break;

                default:
                    printf(
                        TLS_SERVER "mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }
            break;
        }

        len = ret;
        printf(TLS_SERVER "%d bytes received from client:\n", len);

        // For testing purpose, valdiate received data's content and size
#ifdef ADD_TEST_CHECKING
        if (((size_t)len != CLIENT_PAYLOAD_SIZE) ||
            (memcmp(CLIENT_PAYLOAD, buf, (size_t)len) != 0))
        {
            printf(
                TLS_SERVER
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                (int)CLIENT_PAYLOAD_SIZE,
                len);
            ret = MBEDTLS_EXIT_FAILURE;
            goto done;
        }
        printf(TLS_SERVER
               "Verified: the contents of client payload were expected\n\n");
#endif
        if ((size_t)ret == CLIENT_PAYLOAD_SIZE)
            break;
    } while (1);

    // Write a response back to the client
    printf(TLS_SERVER "-----> Write to client:\n");
    len = snprintf((char*)buf, sizeof(buf) - 1, SERVER_PAYLOAD);

    while ((ret = mbedtls_ssl_write(ssl, buf, (size_t)len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            printf(TLS_SERVER "failed\n  ! peer closed the connection\n\n");
            goto waiting_for_connection_request;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed\n  ! mbedtls_ssl_write returned %d\n\n",
                ret);
            goto done;
        }
    }

    len = ret;
    printf(TLS_SERVER "%d bytes written to client\n\n", len);
    printf(TLS_SERVER "Closing the connection...\n");
    while ((ret = mbedtls_ssl_close_notify(ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed! mbedtls_ssl_close_notify returned %d\n\n",
                ret);
            goto waiting_for_connection_request;
        }
    }

    ret = 0;

    if (keep_server_up)
        goto waiting_for_connection_request;

done:
    return ret;
}

int setup_tls_server(char* server_port, bool keep_server_up)
{
    int ret = 0;
    oe_result_t result = OE_FAILURE;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_cache_context cache;
    mbedtls_net_context listen_fd, client_fd;
    const char* pers = "tls_server";

    // Explicitly enabling features
    if ((result = oe_load_module_host_resolver()) != OE_OK)
    {
        printf(
            TLS_SERVER "oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
    {
        printf(
            TLS_SERVER "oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // init mbedtls objects
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cache_init(&cache);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    oe_verifier_initialize();

    printf(
        TLS_SERVER "Setup the listening TCP socket on SERVER_IP= [%s] "
                   "server_port = [%s]\n",
        SERVER_IP,
        server_port);
    if ((ret = mbedtls_net_bind(
             &listen_fd, SERVER_IP, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_net_bind returned %d\n", ret);
        goto exit;
    }

    printf(
        TLS_SERVER "mbedtls_net_bind returned successfully. (listen_fd = %d)\n",
        listen_fd.fd);

    printf(TLS_SERVER "Seeding the random number generator (RNG)\n");
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        printf(
            TLS_SERVER "failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // Configure server SSL settings
    ret = configure_server_ssl(
        &ssl, &conf, &cache, &ctr_drbg, &server_cert, &pkey);
    if (ret != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

    // handle communication
    ret = handle_communication_until_done(
        &ssl, &listen_fd, &client_fd, keep_server_up);
    if (ret != 0)
    {
        printf(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:

    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf(TLS_SERVER "Last error was: %d - %s\n\n", ret, error_buf);
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
    oe_verifier_shutdown();
    fflush(stdout);
    return (ret);
}
