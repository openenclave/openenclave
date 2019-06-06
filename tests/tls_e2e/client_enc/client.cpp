// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
//#define OE_NEED_STDC_NAMES
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>

#include <openenclave/corelibc/arpa/inet.h>
#include <openenclave/corelibc/netdb.h>
#include <openenclave/corelibc/netinet/in.h>
#include <openenclave/internal/posix/device.h>

//#include <bits/stdfile.h> // For stderr & FILE
#include <errno.h> // For errno & error defs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// clang-format off
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
    int launch_tls_client(
        struct tls_control_args* config,
        char* server_name,
        char* server_port);
    int setup_tls_server(struct tls_control_args* config, char* server_port);
};

struct tls_control_args g_control_config;

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection reqest
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;

    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");
    if (g_control_config.fail_enclave_identity_verifier_callback)
        goto done;

    // Check the enclave's security version
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity->security_version checking failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves In a real scenario,
    // custom id checking should be done here
    OE_TRACE_INFO("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nparsed_report->identity.signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

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

int configure_client_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* client_cert,
    mbedtls_pk_context* private_key)
{
    int ret = 1;
    oe_result_t result = OE_FAILURE;

    OE_TRACE_INFO("Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(client_cert, private_key);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR("failed with %s\n", oe_result_str(result));
        ret = 1;
        goto done;
    }

    OE_TRACE_INFO("Setting up the SSL/TLS structure...\n");

    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_CLIENT,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        OE_TRACE_ERROR(
            "failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        goto done;
    }

    // set up random engine
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    // set debug function
    mbedtls_ssl_conf_dbg(conf, debug_print, stdout);

    // Customized certificate validation will replace TLS default operation, set
    // authmod to OPTIONAL here Set the certificate verification mode to
    // MBEDTLS_SSL_VERIFY_OPTIONAL, which peer certificate is checked, however
    // the handshake continues even if verification failed;
    // mbedtls_ssl_get_verify_result() can be called after the handshake is
    // complete.
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
        OE_TRACE_ERROR(
            "failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        goto done;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        OE_TRACE_ERROR("failed! mbedtls_ssl_setup returned %d\n", ret);
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
    int ret = 1;
    uint32_t uret = 1;
    oe_result_t result = OE_FAILURE;
    int len = 0;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned char buf[1024];
    const char* pers = "ssl_client";
    static bool oe_module_loaded = false;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context pkey;

    // Explicitly enable socket and resolver features, which are required by
    // mbedtls' TLS feature
    if (!oe_module_loaded)
    {
        OE_CHECK(oe_load_module_host_socket_interface());
        OE_CHECK(oe_load_module_host_resolver());
        oe_module_loaded = true;
    }

    mbedtls_debug_set_threshold(DEBUG_LEVEL);

    // Initialize the RNG and the session data
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&pkey);

    g_control_config = *config;
    if (CLIENT_REQUEST_PAYLOAD_SIZE != strlen(CLIENT_GET_REQUEST))
    {
        OE_TRACE_ERROR(
            "Error: this client's request payload size does not match"
            " what's defined in CLIENT_REQUEST_PAYLOAD_SIZE, please fix it\n");
        exit_code = MBEDTLS_EXIT_FAILURE;
        goto done;
    }

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        OE_TRACE_ERROR("Failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto done;
    }

    //
    // Start the connection
    //
    OE_TRACE_INFO(
        "client (E)Connecting to tcp/%s/%s...\n", server_name, server_port);
    if ((ret = mbedtls_net_connect(
             &server_fd, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        OE_TRACE_ERROR(
            "Failed\n  ! mbedtls_net_connect returned %d (errno=%d)\n",
            ret,
            errno);
        goto done;
    }

    OE_TRACE_INFO("Connected to server @%s.%s\n", server_name, server_port);

    //
    // Configure client SSL settings
    //
    ret = configure_client_ssl(&ssl, &conf, &ctr_drbg, &client_cert, &pkey);
    if (ret != 0)
    {
        OE_TRACE_ERROR("Failed! mbedtls_net_connect returned %d\n", ret);
        goto done;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, server_name)) != 0)
    {
        OE_TRACE_ERROR("Failed! mbedtls_ssl_set_hostname returned %d\n", ret);
        goto done;
    }

    mbedtls_ssl_set_bio(
        &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    //
    // Handshake
    //
    OE_TRACE_INFO("Performing the SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            OE_TRACE_ERROR(
                "Failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto done;
        }
    }

    uret = mbedtls_ssl_get_verify_result(&ssl);
    if (uret != 0)
    {
        OE_TRACE_ERROR(
            "client mbedtls_ssl_handshake failed with uret = 0x%x\n", uret);
        mbedtls_ssl_close_notify(&ssl);
        exit_code = MBEDTLS_EXIT_FAILURE;
        goto done;
    }
    OE_TRACE_INFO("client mbedtls_ssl_handshake ok\n");

    //
    // Start simple communication with the TLS server
    //

    // Write an GET request to the server
    OE_TRACE_INFO("Write to server-->:");
    //	len = sprintf((char *)buf, CLIENT_GET_REQUEST);
    len = snprintf((char*)buf, sizeof(buf) - 1, CLIENT_GET_REQUEST);
    while ((ret = mbedtls_ssl_write(&ssl, buf, (size_t)len)) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            OE_TRACE_ERROR("Failed! mbedtls_ssl_write returned %d\n", ret);
            goto done;
        }
    }

    len = ret;
    OE_TRACE_INFO("%d bytes written\n%s", len, (char*)buf);

    // Read the HTTP response from server
    OE_TRACE_INFO("<-- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, (size_t)len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
            OE_TRACE_ERROR("Failed! mbedtls_ssl_read returned %d\n\n", ret);
            exit_code = ret;
            goto done;
            // break;
        }

        if (ret < 0)
        {
            OE_TRACE_ERROR("Failed! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0)
        {
            OE_TRACE_INFO("\n\nEOF\n\n");
            break;
        }
        len = ret;
        OE_TRACE_INFO(" %d bytes read\n%s", len, (char*)buf);
        if (len != SERVER_RESPONSE_PAYLOAD_SIZE) // hard coded to match server
        {
            OE_TRACE_ERROR(
                "ERROR: expected reading %d bytes but only got %d bytes\n",
                SERVER_RESPONSE_PAYLOAD_SIZE,
                len);
            exit_code = MBEDTLS_EXIT_FAILURE;
            goto done;
        }
        else
        {
            OE_TRACE_INFO("Client done reading server data\n");
            break;
        }
    } while (1);

    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
done:
    if (exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        OE_TRACE_ERROR("Last error was: %d - %s\n", ret, error_buf);
    }

    mbedtls_net_free(&server_fd);
    // free certificate resource
    mbedtls_x509_crt_free(&client_cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    // free ssl resource
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (exit_code);
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
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
