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
#include "../../../common/utility.h"

extern "C"
{
    int setup_tls_server(char* server_port, bool keep_server_up);
};

#define MAX_ERROR_BUFF_SIZE 256
char error_buf[MAX_ERROR_BUFF_SIZE];
unsigned char buf[1024];

#define SERVER_IP "0.0.0.0"

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"         \
    "A message from TLS server inside enclave\r\n"

// This routine was created to demonstrate a simple communication scenario
// between a TLS client and an TLS server. In a real TLS server app, you
// definitely will have to do more that just receiving a single message
// from a client.
int handle_communication_until_done()
{
    int ret = 0;
    int len = 0;

    return ret;
}

int load_oe_modules()
{
    int ret = -1;
    oe_result_t result = OE_FAILURE;

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
    ret = 0;
exit:
    return ret;
}

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

void init_openssl_library()
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
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

int load_ssl_certificates_and_keys(SSL_CTX* ctx, X509*& cert, EVP_PKEY*& pkey)
{
    int ret = -1;
    SSL_CTX_set_ecdh_auto(ctx, 1);
    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;
    uint8_t* private_key_buf = NULL;
    size_t private_key_buf_size = 0;
    const unsigned char* cert_buf_ptr = NULL;

    if (generate_certificate_and_pkey_buffers(
            output_cert,
            output_cert_size,
            private_key_buf,
            private_key_buf_size) == OE_FAILURE)
    {
        printf(" failed generating certificate and private key buffers \n");
        goto exit;
    }

    // temporary buffer required as if d2i_x509 call is successful cert_buf_ptr
    // is incremented to the byte following the parsed data. sending
    // cert_buf_ptr as argument will keep output_cert pointer undisturbed.
    cert_buf_ptr = output_cert;

    if ((cert = d2i_X509(NULL, &cert_buf_ptr, (long)output_cert_size)) == NULL)
    {
        printf(TLS_SERVER
               "Failed to convert DER fromat certificate to X509 structure\n");
        goto exit;
    }

    if (!SSL_CTX_use_certificate(ctx, cert))
    {
        printf(TLS_SERVER "Cannot load certificate on the server\n");
        goto exit;
    }

    if ((pkey = PEM_read_bio_PrivateKey(
             BIO_new_mem_buf((void*)private_key_buf, -1), NULL, 0, NULL)) ==
        NULL)
    {
        printf(TLS_SERVER
               "Failed to convert private key buffer into EVP_KEY format\n");
        goto exit;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
    {
        printf(TLS_SERVER "Cannot load private key on the server\n");
        goto exit;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf(TLS_SERVER
               "Private key does not match the public certificate\n");
        goto exit;
    }

    ret = 0;
exit:
    cert_buf_ptr = NULL;
    oe_free_key(private_key_buf, private_key_buf_size, NULL, 0);
    oe_free_attestation_certificate(output_cert);
    return ret;
}

int create_listner_socket(int port, int& server_socket)
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

int setup_tls_server(char* server_port, bool keep_server_up)
{
    int ret = 0;
    int server_socket_fd;
    int server_port_num;

    ENGINE* eng = NULL;
    SSL_CTX* ssl_server_ctx = NULL;
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    /* Load host resolver and socket interface modules explicitly*/
    if (load_oe_modules() != 0)
    {
        printf(TLS_SERVER "loading required oe modules failed \n");
        goto exit;
    }

    /* Initialize openssl random engine as mentioned in */
    if (init_openssl_rand_engine(eng) != 0)
    {
        printf(TLS_SERVER " initializing openssl random engine failed \n");
        goto exit;
    }

    // initialize openssl library and register algorithms
    init_openssl_library();
    if (SSL_library_init() < 0)
    {
        printf(TLS_SERVER " could not initialize the OpenSSL library !\n");
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
    if (create_listner_socket(server_port_num, server_socket_fd) != 0)
    {
        printf(TLS_SERVER " unable to create listener socket on the server\n ");
        goto exit;
    }

    /* Handle connections */
    while (1)
    {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL* ssl;
        printf(" waiting for client connection \n");
        int client = accept(server_socket_fd, (struct sockaddr*)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        ssl = SSL_new(ssl_server_ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0)
        {
            printf("ssl accept failed \n");
            ERR_print_errors_fp(stderr);
        }
        else
        {
            SSL_write(ssl, SERVER_PAYLOAD, strlen(SERVER_PAYLOAD));
        }
        printf(" cleaning up the resources \n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        break;
    }

exit:
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();
    SSL_CTX_free(ssl_server_ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    fflush(stdout);
    return (ret);
}
