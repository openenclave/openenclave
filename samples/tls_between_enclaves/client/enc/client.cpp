// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
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

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg);

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define DEBUG_LEVEL 1

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

int configure_client_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* private_key)
{
    int ret = 1;
    oe_result_t result = OE_FAILURE;

    printf("Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(client_cert, private_key);
    if (result != OE_OK)
    {
        printf("failed with %s\n", oe_result_str(result));
        ret = 1;
        goto exit;
    }

    printf("Setting up the SSL/TLS structure...\n");

    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf("failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        goto exit;
    }

    printf("mbedtls_ssl_config_defaults returned successfully\n");

    // set up random engine
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    // set debug function
    mbedtls_ssl_conf_dbg(conf, my_debug, stdout);

    // Set the certificate verification mode to MBEDTLS_SSL_VERIFY_OPTIONAL
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, cert_verify_callback, NULL);

    // enable TLS server to send a list of acceptable CAs in CertificateRequest
    // messages. mbedtls_ssl_conf_cert_req_ca_list( &conf,
    // MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED); mbedtls_ssl_conf_ca_chain(conf,
    // server_cert->next, NULL);

    // Set own certificate chain and private key.
    // Note
    // own_cert should contain in order from the bottom up your certificate
    // chain. The top certificate (self-signed) can be omitted. On server, this
    // function can be called multiple times to provision more than
    //            one cert/key pair (eg one ECDSA, one RSA with SHA-256, one RSA
    //            with SHA-1). An adequate certificate will be selected
    //            according to the client's advertised capabilities. In case
    //            multiple certificates are adequate, preference is given to the
    //            one set by the first call to this function, then second, etc.
    // On client, only the first call has any effect. That is, only one client
    // certificate
    //            can be provisioned. The server's preferences in its
    //            CertficateRequest message will be ignored and our only cert
    //            will be sent regardless of whether it matches those
    //            preferences - the server can then decide what it wants to do
    //            with it.
    //
    // The provided pk_key needs to match the public key in the first
    // certificate in own_cert, or all handshakes using that certificate will
    // fail. It is your responsibility to ensure that; this function will not
    // perform any check. You may use mbedtls_pk_check_pair() in order to
    // perform this check yourself, but be aware that this function can be
    // computationally expensive on some key types.

    if ((ret = mbedtls_ssl_conf_own_cert(conf, client_cert, private_key)) != 0)
    {
        printf("failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        printf("failed! mbedtls_ssl_setup returned %d\n", ret);
        goto exit;
    }

    ret = 0;

exit:
    fflush(stdout);
    return ret;
}

int launch_tls_client(char* server_name, char* server_port)
{
    int ret = 1;
    int len = 0;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    uint32_t flags;
    unsigned char buf[1024];
    const char* pers = "ssl_client";
    oe_result_t result = OE_FAILURE;

    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context pkey;

    // Explicitly enabling features
    // Explicitly enabling features
    if ((result = oe_load_module_hostresolver()) != OE_OK)
    {
        printf(
            "oe_load_module_hostresolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    if ((result = oe_load_module_hostsock()) != OE_OK)
    {
        printf(
            "oe_load_module_hostsock failed with %s\n", oe_result_str(result));
        goto exit;
    }

    // Initialize mbedtls objects
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&pkey);

#ifdef ADD_TEST_CHECKING
    if (CLIENT_REQUEST_PAYLOAD_SIZE != strlen(GET_REQUEST))
    {
        printf(
            "Error: this client's request payload size does not match"
            " what's defined in CLIENT_REQUEST_PAYLOAD_SIZE, please fix it\n");
        exit_code = MBEDTLS_EXIT_FAILURE;
        goto exit;
    }
#endif

    printf("\nSeeding the random number generator...\n");
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        printf("Failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    printf("mbedtls_ctr_drbg_seed done\n");

    //
    // Start the connection
    //
    printf("Connecting to tcp: %s/%s...\n", server_name, server_port);

    if ((ret = mbedtls_net_connect(
             &server_fd, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(
            "Failed\n  ! mbedtls_net_connect returned %d errno=%d\n",
            ret,
            errno);
        exit_code = ret;
        goto exit;
    }

    printf("Connected to server @%s.%s\n", server_name, server_port);

    //
    // Configure client SSL settings
    //
    ret = configure_client_ssl(&ssl, &conf, &ctr_drbg, &client_cert, &pkey);
    if (ret != 0)
    {
        printf("Failed! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, server_name)) != 0)
    {
        printf("Failed! mbedtls_ssl_set_hostname returned %d\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(
        &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    //
    // Handshake
    //
    printf("Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                "Failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto exit;
        }
    }

    printf("mbedtls_ssl_handshake ok\n");

    //
    // Start simple communication with the TLS server
    //

    // Write an GET request to the server
    printf("Write to server-->:");
    len = sprintf((char*)buf, GET_REQUEST);
    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf("Failed! mbedtls_ssl_write returned %d\n", ret);
            goto exit;
        }
    }

    len = ret;
    printf("%d bytes written\n%s", len, (char*)buf);

    printf("Read the HTTP response from server:\n");
    printf("<-- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (ret < 0)
        {
            printf("Failed! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0)
        {
            printf("\n\nEOF\n\n");
            break;
        }
        len = ret;
        printf(" %d bytes read\n%s", len, (char*)buf);
        if (len != SERVER_RESPONSE_PAYLOAD_SIZE) // hard coded to match server
        {
            printf(
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                SERVER_RESPONSE_PAYLOAD_SIZE,
                len);
            exit_code = MBEDTLS_EXIT_FAILURE;
            goto exit;
        }
        else
        {
            printf("Client done reading server data\n");
            break;
        }
    } while (1);

    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
exit:
    if (exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf("Last error was: %d - %s\n", ret, error_buf);
    }

    mbedtls_net_free(&server_fd);

    // free mbedtls objects
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        ret = 0;

    fflush(stdout);
    return (exit_code);
}
