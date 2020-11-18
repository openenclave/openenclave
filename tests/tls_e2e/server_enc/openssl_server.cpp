// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/syscall/device.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
// clang-format on

#include "tls_e2e_t.h"
#include "../common/openssl_utility.h"

extern "C"
{
    int setup_tls_server(struct tls_control_args* config, char* server_port);
    int launch_tls_client(
        struct tls_control_args* config,
        char* server_name,
        char* server_port);
};

struct tls_control_args g_control_config;

int launch_tls_client(
    struct tls_control_args* config,
    char* server_name,
    char* server_port)
{
    (void)config;
    (void)server_name;
    (void)server_port;
    return 0;
}

int create_listener_socket(uint16_t port, int& server_socket)
{
    int ret = -1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        OE_TRACE_ERROR(TLS_SERVER "socket creation failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        OE_TRACE_ERROR(TLS_SERVER "Unable to bind socket to the port \n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        OE_TRACE_ERROR(TLS_SERVER "Unable to open socket for listening \n");
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
    OE_TRACE_INFO(TLS_SERVER " waiting for client connection \n");

    struct sockaddr_in addr;
    uint len = sizeof(addr);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&addr, &len);

    if (client_socket_fd < 0)
    {
        OE_TRACE_ERROR(TLS_SERVER "Unable to accept the client request \n");
        goto exit;
    }

    // create a new SSL structure for a connection
    if ((ssl_session = SSL_new(ssl_server_ctx)) == NULL)
    {
        OE_TRACE_ERROR(TLS_SERVER
                       "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    SSL_set_fd(ssl_session, client_socket_fd);

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake
    if (SSL_accept(ssl_session) <= 0)
    {
        OE_TRACE_ERROR(TLS_SERVER " SSL handshake failed \n");
        ret = -0x3000; // To match with SSL handshake error for mbedtls so that
                       // same error return code is compared for failure test
                       // cases
        goto exit;
    }

    OE_TRACE_INFO(TLS_SERVER "<---- Read from client:\n");
    if (read_from_session_peer(
            ssl_session, CLIENT_GET_REQUEST, sizeof(CLIENT_GET_REQUEST)) != 0)
    {
        OE_TRACE_INFO(" Read from client failed \n");
        goto exit;
    }

    OE_TRACE_INFO(TLS_SERVER "<---- Write to client:\n");
    if (write_to_session_peer(
            ssl_session, SERVER_HTTP_RESPONSE, sizeof(SERVER_HTTP_RESPONSE)) !=
        0)
    {
        OE_TRACE_INFO(TLS_SERVER " Write to client failed \n");
        goto exit;
    }
    OE_TRACE_INFO(TLS_SERVER " writing completed \n");
    if (keep_server_up)
        goto waiting_for_connection_request;

    ret = 0;
exit:
    return ret;
}

int setup_tls_server(struct tls_control_args* config, char* server_port)
{
    OE_TRACE_INFO(TLS_SERVER " called setup tls server");
    int ret = -1;
    int server_ready_ret = 1;

    int server_socket_fd = -1;
    int client_socket_fd = -1;
    uint16_t server_port_num = 0;

    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    SSL_CTX* ssl_server_ctx = NULL;
    SSL* ssl_session = NULL;

    g_control_config = *config;

    /* Load host resolver and socket interface modules explicitly*/
    if (load_oe_modules() != OE_OK)
    {
        OE_TRACE_ERROR(TLS_SERVER "loading required oe modules failed \n");
        goto exit;
    }

    if ((ssl_server_ctx = SSL_CTX_new(TLS_server_method())) == NULL)
    {
        OE_TRACE_ERROR(TLS_SERVER " unable to create a new SSL context\n");
        goto exit;
    }

    if (initalize_ssl_context(ssl_server_ctx) != 0)
    {
        OE_TRACE_ERROR(TLS_SERVER " unable to create a new SSL context\n ");
        goto exit;
    }

    if (load_ssl_certificates_and_keys(ssl_server_ctx, cert, pkey) != 0)
    {
        OE_TRACE_ERROR(
            TLS_SERVER
            " unable to load certificate and private key on the server\n ");
        goto exit;
    }

    sscanf(server_port, "%d", &server_port_num); // conver to char* to int
    if (create_listener_socket(server_port_num, server_socket_fd) != 0)
    {
        OE_TRACE_ERROR(TLS_SERVER
                       " unable to create listener socket on the server\n ");
        goto exit;
    }

    server_is_ready(&server_ready_ret);

    // handle communication
    ret = handle_communication_until_done(
        server_socket_fd, client_socket_fd, ssl_server_ctx, ssl_session, false);

    if (ret != 0)
    {
        OE_TRACE_ERROR(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

    ret = 0;
exit:
    if (ret != 0)
    {
        int init_failed_ret;
        if (server_ready_ret != 0)
        {
            server_initialization_failed(&init_failed_ret);
        }
    }

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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
