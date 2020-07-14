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

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl_cache.h>
// clang-format on

#include "tls_e2e_t.h"
#include "../common/utility.h"

extern "C"
{
    int setup_tls_server(struct tls_control_args* config, char* server_port);
    int launch_tls_client(
        struct tls_control_args* config,
        char* server_name,
        char* server_port);
};

#define SERVER_IP "127.0.0.1"

struct tls_control_args g_control_config;

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection reqest
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;
    (void)arg;

    if (g_control_config.fail_enclave_identity_verifier_callback)
        goto done;

    OE_TRACE_INFO("Server:enclave_identity_verifier is called with enclave "
                  "identity information:\n");

    // the enclave's security version
    OE_TRACE_INFO(
        "identity->security_version = %d\n", identity->security_version);

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves In a real scenario,
    // custom id checking should be done here
    OE_TRACE_INFO("identity->unique_id(MRENCLAVE) :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->unique_id[i]);

    OE_TRACE_INFO("\nidentity->signer_id(MRSIGNER) :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    // On a real enclave product, this is the place to check again the enclave
    // signing key by calling function like verify_mrsigner below. However, we
    // are not siging test cases, so this checking will be skipped.
    // tls_between_enclaves sample will have code show how to dothis checking if
    // (!verify_mrsigner((char *)OTHER_ENCLAVE_PUBLIC_KEY,
    //                     sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
    //                     identity->signer_id,
    //                     sizeof(identity->signer_id)))
    // {
    //     OE_TRACE_ERROR("failed:mrsigner not equal!\n");
    //     goto done;
    // }

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;

done:
    return result;
}

static void debug_print(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    ((void)level);
    ((void)ctx);
    OE_TRACE_INFO("%s:%04d: %s", file, line, str);
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

    OE_TRACE_INFO("Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(server_cert, pkey);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR("failed with %s\n", oe_result_str(result));
        ret = 1;
        goto done;
    }

    OE_TRACE_INFO("Setting up the SSL configuration....\n");
    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        OE_TRACE_ERROR(
            "failed\n  ! mbedtls_ssl_config_defaults returned failed %d\n",
            ret);
        goto done;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(conf, debug_print, stdout);
    mbedtls_ssl_conf_session_cache(
        conf, cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    // need to set authmode mode to OPTIONAL for requesting client certificate
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, cert_verify_callback, NULL);
    mbedtls_ssl_conf_ca_chain(conf, server_cert->next, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(conf, server_cert, pkey)) != 0)
    {
        OE_TRACE_ERROR(
            "failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        goto done;
    }
    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        OE_TRACE_ERROR("failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
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
    (void)config;
    (void)server_name;
    (void)server_port;
    mbedtls_printf("Calling server:launch_tls_client: Never reach here\n");
    return 0;
}
int setup_tls_server(struct tls_control_args* config, char* server_port)
{
    int ret = 0;
    int server_ready_ret = 1;
    int len = 0;
    uint32_t uret = 1;
    oe_result_t result = OE_FAILURE;
    static bool oe_module_loaded = false;

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

    // Explicitly enable socket and resolver features, which are required by
    // mbedtls' TLS feature
    if (!oe_module_loaded)
    {
        OE_CHECK(oe_load_module_host_socket_interface());
        OE_CHECK(oe_load_module_host_resolver());
        oe_module_loaded = true;
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

#if !defined(NDEBUG)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    g_control_config = *config;

    OE_TRACE_INFO(
        "Setup the listening TCP socket on SERVER_IP= [%s] server_port = "
        "[%s]\n",
        SERVER_IP,
        server_port);
    if ((ret = mbedtls_net_bind(
             &listen_fd, SERVER_IP, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        OE_TRACE_ERROR(" failed\n  ! mbedtls_net_bind returned %d\n", ret);
        goto done;
    }

    OE_TRACE_INFO(
        "mbedtls_net_bind returned successfully. (listen_fd = %d)\n",
        listen_fd.fd);
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        OE_TRACE_ERROR(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto done;
    }

    ret = configure_server_ssl(
        &ssl, &conf, &cache, &ctr_drbg, &server_cert, &pkey);
    if (ret != 0)
    {
        OE_TRACE_ERROR(
            " failed\n  ! Configure server SSL settings: configure_server_ssl "
            "returned %d\n",
            ret);
        goto done;
    }

waiting_for_connection_request:

    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        OE_TRACE_ERROR("Last error was: %d - %s\n", ret, error_buf);
    }

    // reset ssl setup and client_fd to prepare for the new TLS connection
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);

    OE_TRACE_INFO("Waiting for a remote connection request...\n");
    server_is_ready(&server_ready_ret);
    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0)
    {
        char errbuf[512];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        OE_TRACE_ERROR(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        OE_TRACE_ERROR("%s\n", errbuf);
        goto done;
    }
    OE_TRACE_INFO(
        "mbedtls_net_accept returned successfully.(listen_fd = %d) (client_fd "
        "= %d)\n",
        listen_fd.fd,
        client_fd.fd);

    // set up bio callbacks
    mbedtls_ssl_set_bio(
        &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    OE_TRACE_INFO("Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            OE_TRACE_ERROR(
                " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            goto done;
        }
    }

    uret = mbedtls_ssl_get_verify_result(&ssl);
    if (uret != 0)
    {
        OE_TRACE_ERROR(
            "server mbedtls_ssl_handshake failed with uret = 0x%x\n", uret);
        mbedtls_ssl_close_notify(&ssl);
        ret = 1;
        goto done;
    }

    OE_TRACE_INFO("server mbedtls_ssl_handshake done successfully\n");

    // Read client's request
    OE_TRACE_INFO("< Read from client:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, (size_t)len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    OE_TRACE_INFO("connection was closed gracefully\n");
                    goto done;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    OE_TRACE_INFO("connection was reset by peer\n");
                    break;

                default:
                    OE_TRACE_INFO("mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }
            break;
        }

        len = ret;
        OE_TRACE_INFO(" %d bytes read\n\n[%s]", len, (char*)buf);

        if (len != CLIENT_REQUEST_PAYLOAD_SIZE) // hard coded to match client
        {
            OE_TRACE_INFO(
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                CLIENT_REQUEST_PAYLOAD_SIZE,
                len);
            ret = 1;
            goto done;
        }

        if (ret > 0)
            break;
    } while (1);

    // Write a response back to the client with selected ciphersuite name
    OE_TRACE_INFO("> Write to client:\n");
    len = snprintf(
        (char*)buf,
        sizeof(buf) - 1,
        SERVER_HTTP_RESPONSE,
        mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, (size_t)len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            OE_TRACE_ERROR(" failed\n  ! peer closed the connection\n\n");
            goto waiting_for_connection_request;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            OE_TRACE_ERROR(
                " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto done;
        }
    }

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

        // Mark server as done initializing if server_is_ready was never called
        // to avoid deadlock
        int init_failed_ret;
        if (server_ready_ret != 0)
            server_initialization_failed(&init_failed_ret);
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
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
