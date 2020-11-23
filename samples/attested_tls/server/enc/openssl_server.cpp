// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <arpa/inet.h>
#include <openenclave/enclave.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../../common/openssl_utility.h"

extern "C"
{
    int setup_tls_server(char* server_port, bool keep_server_up);
};

int init_openssl_rand_engine(ENGINE*& eng)
{
    int ret = -1;
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
    {
        goto exit;
    }

    if (!ENGINE_init(eng))
    {
        goto exit;
    }

    if (!ENGINE_set_default(eng, ENGINE_METHOD_RAND))
    {
        goto exit;
    }

    ret = 0;
exit:
    return ret;
}

int initalize_ssl_context(SSL_CTX*& ctx)
{
    int ret = -1;
    const SSL_METHOD* method;
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
    {
        printf(TLS_SERVER " unable to create a new SSL context\n");
        goto exit;
    }
    // choose TLSv1.2 by excluding SSLv2, SSLv3 ,TLS 1.0 and TLS 1.1
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    ret = 0;
exit:
    return ret;
}

int create_listener_socket(int port, int& server_socket)
{
    int ret = -1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        printf(TLS_SERVER "socket creation failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        printf(TLS_SERVER "Unable to bind socket to the port \n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        printf(TLS_SERVER "Unable to open socket for listening \n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int handle_communication_until_done(
    int& server_socket_fd,
    int& client_socket_fd,
    SSL_CTX*& ssl_server_ctx,
    SSL*& ssl_session,
    bool keep_server_up)
{
    int ret = -1;

waiting_for_connection_request:

    // reset ssl_session setup and client_socket_fd to prepare for the new TLS
    // connection
    close(client_socket_fd);
    SSL_free(ssl_session);
    printf(TLS_SERVER " waiting for client connection \n");

    struct sockaddr_in addr;
    uint len = sizeof(addr);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&addr, &len);

    if (client_socket_fd < 0)
    {
        printf(TLS_SERVER "Unable to accept the client request \n");
        goto exit;
    }

    // create a new SSL structure for a connection
    if ((ssl_session = SSL_new(ssl_server_ctx)) == NULL)
    {
        printf(TLS_SERVER
               "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    SSL_set_fd(ssl_session, client_socket_fd);

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake
    if (SSL_accept(ssl_session) <= 0)
    {
        printf(TLS_SERVER " SSL handshake failed \n");
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    printf(TLS_SERVER "<---- Read from client:\n");
    if (read_from_session_peer(
            ssl_session, CLIENT_PAYLOAD, CLIENT_PAYLOAD_SIZE) != 0)
    {
        printf(TLS_SERVER " Read from client failed \n");
        goto exit;
    }

    printf(TLS_SERVER "<---- Write to client:\n");
    if (write_to_session_peer(
            ssl_session, SERVER_PAYLOAD, strlen(SERVER_PAYLOAD)) != 0)
    {
        printf(TLS_SERVER " Write to client failed \n");
        goto exit;
    }

    if (keep_server_up)
        goto waiting_for_connection_request;

    ret = 0;
exit:
    return ret;
}

int setup_tls_server(char* server_port, bool keep_server_up)
{
    int ret = 0;
    int server_socket_fd;
    int client_socket_fd;
    int server_port_num;

    ENGINE* eng = NULL;
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    SSL_CTX* ssl_server_ctx = NULL;
    SSL* ssl_session = NULL;

    /* Load host resolver and socket interface modules explicitly*/
    if (load_oe_modules() != OE_OK)
    {
        printf(TLS_SERVER "loading required oe modules failed \n");
        goto exit;
    }

    /* Initialize openssl random engine as mentioned in*/
    if (init_openssl_rand_engine(eng) != 0)
    {
        printf(TLS_SERVER " initializing openssl random engine failed \n");
        goto exit;
    }

    if (initalize_ssl_context(ssl_server_ctx) != 0)
    {
        printf(TLS_SERVER " unable to create a new SSL context\n ");
        goto exit;
    }

    if (load_ssl_certificates_and_keys(ssl_server_ctx, cert, pkey) != 0)
    {
        printf(TLS_SERVER
               " unable to load certificate and private key on the server\n ");
        goto exit;
    }

    sscanf(server_port, "%d", &server_port_num); // conver to char* to int
    if (create_listener_socket(server_port_num, server_socket_fd) != 0)
    {
        printf(TLS_SERVER " unable to create listener socket on the server\n ");
        goto exit;
    }

    // handle communication
    ret = handle_communication_until_done(
        server_socket_fd,
        client_socket_fd,
        ssl_server_ctx,
        ssl_session,
        keep_server_up);
    if (ret != 0)
    {
        printf(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:
    ENGINE_finish(eng); // clean up openssl random engine resources
    ENGINE_free(eng);
    ENGINE_cleanup();

    close(client_socket_fd); // close the socket connections
    close(server_socket_fd);

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }
    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    return (ret);
}
