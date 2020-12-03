// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/syscall/arpa/inet.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/netdb.h>
#include <openenclave/internal/syscall/netinet/in.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/internal/tests.h>

#include <arpa/inet.h>
#include <errno.h> // For errno & error defs
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "../common/openssl_utility.h"
#include "tls_e2e_t.h"

extern "C"
{
    int launch_tls_client(
        struct tls_control_args* config,
        char* server_name,
        char* server_port);
    int setup_tls_server(struct tls_control_args* config, char* server_port);
};

struct tls_control_args g_control_config;

// create a socket and connect to the server_name:server_port
int create_socket(
    int& client_socket,
    char* server_name,
    uint16_t server_port_num)
{
    int ret = -1;
    struct sockaddr_in ip_of_server;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        OE_TRACE_ERROR(TLS_CLIENT "Socket not created \n");
        goto exit;
    }

    ip_of_server.sin_family = AF_INET;
    ip_of_server.sin_port = htons(server_port_num);
    ip_of_server.sin_addr.s_addr = inet_addr(server_name);

    if (connect(
            client_socket,
            (struct sockaddr*)&ip_of_server,
            sizeof(ip_of_server)) < 0)
    {
        OE_TRACE_ERROR(TLS_CLIENT
                       "Connection failed due to port and ip problems\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

// This routine conducts a simple HTTP request/response communication with
// server
int communicate_with_server(SSL* ssl)
{
    int ret = 1;
    // Write an GET request to the server
    OE_TRACE_INFO(TLS_CLIENT "-----> Write to server:\n");
    if (write_to_session_peer(
            ssl, CLIENT_GET_REQUEST, sizeof(CLIENT_GET_REQUEST)) != 0)
    {
        OE_TRACE_ERROR(TLS_CLIENT " Write to client failed \n");
        goto done;
    }
    // Read the HTTP response from server
    OE_TRACE_INFO(TLS_CLIENT "<---- Read from server:\n");
    if (read_from_session_peer(
            ssl, SERVER_HTTP_RESPONSE, sizeof(SERVER_HTTP_RESPONSE)) != 0)
    {
        OE_TRACE_ERROR(TLS_CLIENT " Read from client failed \n");
        goto done;
    }
    ret = 0;
done:
    return ret;
}

int launch_tls_client(
    struct tls_control_args* config,
    char* server_name,
    char* server_port)
{
    OE_TRACE_INFO(TLS_CLIENT " called setup tls client");
    int ret = -1;
    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;

    SSL_CTX* ssl_client_ctx = nullptr;
    SSL* ssl_session = nullptr;

    int client_socket = -1;
    int error = 0;
    uint16_t server_port_num = 0;

    g_control_config = *config;

    /* Load host resolver and socket interface modules explicitly*/
    if (load_oe_modules() != OE_OK)
    {
        OE_TRACE_ERROR(TLS_CLIENT "loading required oe modules failed \n");
        goto done;
    }

    if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
        OE_TRACE_ERROR(TLS_CLIENT "unable to create a new SSL context\n");
        goto done;
    }

    if (initalize_ssl_context(ssl_client_ctx) != 0)
    {
        OE_TRACE_ERROR(TLS_CLIENT " unable to create a new SSL context\n ");
        goto done;
    }

    if (load_ssl_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
    {
        OE_TRACE_ERROR(
            TLS_CLIENT
            " unable to load certificate and private key on the server\n ");
        goto done;
    }

    if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
        OE_TRACE_ERROR(TLS_CLIENT
                       "Unable to create a new SSL connection state object\n");
        goto done;
    }

    OE_TRACE_INFO(TLS_CLIENT "new ssl conntection getting created \n");
    server_port_num = (uint16_t)atoi(server_port);
    if (create_socket(client_socket, server_name, server_port_num) != 0)
    {
        OE_TRACE_ERROR(
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    // setup ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl_session, client_socket);

    if ((error = SSL_connect(ssl_session)) != 1)
    {
        // SSL_connect returns 0 when handshake failure happens.
        // https://www.openssl.org/docs/man1.0.2/man3/SSL_connect.html
        // SSL_connect return value is stored in new variable 'error' instead of
        // 'ret' unlike other blocks so that handshake failure case return value
        // is not stored as success in ret variable.

        OE_TRACE_ERROR(
            TLS_CLIENT "Error: Could not establish an SSL session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl_session, error));
        goto done;
    }

    OE_TRACE_INFO(
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(ssl_session));

    // start the client server communication
    if ((ret = communicate_with_server(ssl_session)) != 0)
    {
        OE_TRACE_ERROR(
            TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", ret);
        goto done;
    }

    // Free the structures we don't need anymore
    ret = 0;

done:
    if (client_socket != -1)
        close(client_socket);

    if (ssl_session)
        SSL_free(ssl_session);

    if (cert)
        X509_free(cert);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (ssl_client_ctx)
        SSL_CTX_free(ssl_client_ctx);

    OE_TRACE_INFO(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return (ret);
}

int setup_tls_server(struct tls_control_args* config, char* server_port)
{
    (void)config;
    (void)server_port;
    OE_TRACE_INFO("Client: calling setup_tls_server: Never reach here\n");
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
