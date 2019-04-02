// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
#include <mbedtls/ssl_cache.h> // Enable simple SSL cache implementation (MBEDTLS_SSL_CACHE_C)
#include <mbedtls/x509.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "../../common/utility.h"

// TODO:
// Need to fix this path openenclave\include\openenclave\internal\resolver.h
//#include "resolver.h"

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg);

extern "C"
{
    int setup_tls_server(char* server_port);
};

// mbedtls debug levels
// 0 No debug, 1 Error, 2 State change, 3 Informational, 4 Verbose
#define DEBUG_LEVEL 1
#define SERVER_IP "127.0.0.1"

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

// If set, the verify callback is called for each certificate in the chain.
// The verification callback is supposed to return 0 on success. Otherwise, the
// verification failed.
static int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags)
{
    oe_result_t result = OE_FAILURE;
    int ret = 1;
    unsigned char* cert_buf = NULL;
    size_t cert_size = 0;

    (void)data;
    (void)flags;

    printf(" cert_verify_callback with depth = %d\n", depth);

    cert_buf = crt->raw.p;
    cert_size = crt->raw.len;

    printf("crt->version = %d\n", crt->version);
    printf("cert_size = %zu\n", cert_size);

    if (cert_size <= 0)
        goto exit;

    result = oe_verify_tls_cert(
        cert_buf, cert_size, enclave_identity_verifier_callback, NULL);
    if (result != OE_OK)
    {
        printf(
            "oe_verify_tls_cert failed with result = %s\n",
            oe_result_str(result));
        goto exit;
    }
    ret = 0;

exit:
    return ret;
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

    printf("Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(server_cert, pkey);
    if (result != OE_OK)
    {
        printf("failed with %s\n", oe_result_str(result));
        ret = 1;
        goto exit;
    }

    printf("Setting up the SSL configuration....\n");
    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(
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
        printf("failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        printf("failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = 0;

exit:
    fflush(stdout);
    return ret;
}

int setup_socket_lib()
{
    oe_resolver_t* host_resolver = NULL;

    printf("server:enclave: setup_socket_lib\n");
    host_resolver = oe_get_hostresolver();
    // TODO: I am not sure why setting it to 2 (lowest priority)
    // what value is appropriate to setfor this resolver_priority !
    (void)oe_register_resolver(2, host_resolver);

    oe_set_default_socket_devid(OE_DEVID_HOST_SOCKET);
    return 0;
}

int setup_tls_server(char* server_port)
{
    int ret = 0;
    int len = 0;
    oe_result_t result = OE_FAILURE;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_cache_context cache;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char* pers = "tls_server";

    setup_socket_lib();

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

    mbedtls_debug_set_threshold(DEBUG_LEVEL);

    printf(
        "Setup the listening TCP socket on SERVER_IP= [%s] server_port = "
        "[%s]\n",
        SERVER_IP,
        server_port);
    if ((ret = mbedtls_net_bind(
             &listen_fd, SERVER_IP, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_bind returned %d\n", ret);
        goto exit;
    }

    printf(
        "mbedtls_net_bind returned successfully. (listen_fd = %d)\n",
        listen_fd.fd);

    printf("Seeding the random number generator (RNG)\n");
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // Configure server SSL settings
    ret = configure_server_ssl(
        &ssl, &conf, &cache, &ctr_drbg, &server_cert, &pkey);
    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

waiting_for_connection_request:
    fflush(stdout);
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf("Last error was: %d - %s\n", ret, error_buf);
    }

    // reset ssl setup and client_fd to prepare for the new TLS connection
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);

    printf("Waiting for a remote connection request...\n");
    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0)
    {
        char errbuf[512];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        printf("%s\n", errbuf);
        goto exit;
    }
    printf(
        "mbedtls_net_accept returned successfully.(listen_fd = %d) (client_fd "
        "= %d) \n",
        listen_fd.fd,
        client_fd.fd);

    // set up bio callbacks
    mbedtls_ssl_set_bio(
        &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf("Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            goto exit;
        }
    }

    printf("mbedtls_ssl_handshake done successfully\n");

    // Read client's request
    printf("< Read from client:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf("connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    printf("connection was reset by peer\n");
                    break;

                default:
                    printf("mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }
            break;
        }

        len = ret;
        printf(" %d bytes read\n\n%s", len, (char*)buf);
#ifdef ADD_TEST_CHECKING
        if (len != CLIENT_REQUEST_PAYLOAD_SIZE) // hard coded to match client
        {
            printf(
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                CLIENT_REQUEST_PAYLOAD_SIZE,
                len);
            ret = MBEDTLS_EXIT_FAILURE;
            goto exit;
        }
#endif
        if (ret > 0)
            break;
    } while (1);

    // Write a response back to the client
    printf("> Write to client:\n");
    len = snprintf(
        (char*)buf,
        sizeof(buf) - 1,
        HTTP_RESPONSE,
        mbedtls_ssl_get_ciphersuite(&ssl));
    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            printf(" failed\n  ! peer closed the connection\n\n");
            goto waiting_for_connection_request;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    printf(" %d bytes written\n", len);

    printf("Closing the connection...\n");
    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("failed! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto waiting_for_connection_request;
        }
    }

    ret = 0;
    goto waiting_for_connection_request;
exit:

    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf("Last error was: %d - %s\n\n", ret, error_buf);
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
    fflush(stdout);
    return (ret);
}
