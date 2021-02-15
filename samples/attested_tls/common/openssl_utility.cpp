// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openssl_utility.h"

oe_result_t generate_certificate_and_pkey(X509*& certificate, EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    const unsigned char* certificate_buffer_ptr = nullptr;
    BIO* mem = nullptr;

    result = generate_key_pair(
        &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);

    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    printf("public_key_buf_size:[%ld]\n", public_key_buffer_size);
    printf("public key used:\n[%s]", public_key_buffer);

    result = oe_generate_attestation_certificate(
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        &output_certificate,
        &output_certificate_size);

    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    // temporary buffer required as if d2i_x509 call is successful
    // certificate_buffer_ptr is incremented to the byte following the parsed
    // data. sending certificate_buffer_ptr as argument will keep
    // output_certificate pointer undisturbed.
    certificate_buffer_ptr = output_certificate;

    if ((certificate = d2i_X509(
             nullptr,
             &certificate_buffer_ptr,
             (long)output_certificate_size)) == nullptr)
    {
        printf("Failed to convert DER format certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buffer, -1);
    if (!mem)
    {
        printf("Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        printf("Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = OE_OK;
done:
    certificate_buffer_ptr = nullptr;
    BIO_free(mem);
    oe_free_key(private_key_buffer, private_key_buffer_size, nullptr, 0);
    oe_free_key(public_key_buffer, public_key_buffer_size, nullptr, 0);
    oe_free_attestation_certificate(output_certificate);
    return result;
}

oe_result_t load_tls_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& certificate,
    EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
    if (generate_certificate_and_pkey(certificate, pkey) != OE_OK)
    {
        printf("Cannot generate certificate and pkey\n");
        goto exit;
    }
    if (!SSL_CTX_use_certificate(ctx, certificate))
    {
        printf("Cannot load certificate on the server\n");
        goto exit;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
    {
        printf("Cannot load private key on the server\n");
        goto exit;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the public certificate\n");
        goto exit;
    }
    result = OE_OK;
exit:
    return result;
}

oe_result_t initalize_ssl_context(SSL_CONF_CTX*& ssl_conf_ctx, SSL_CTX*& ctx)
{
    oe_result_t ret = OE_FAILURE;
    // Configure the SSL context based on Open Enclave's security guidance.
    const char* cipher_list_tlsv12_below =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-"
        "AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-"
        "AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384";
    const char* cipher_list_tlsv13 =
        "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
    const char* supported_curves = "P-521:P-384:P-256";

    SSL_CONF_CTX_set_ssl_ctx(ssl_conf_ctx, ctx);
    SSL_CONF_CTX_set_flags(
        ssl_conf_ctx,
        SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CLIENT);
    int ssl_conf_return_value = -1;
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MinProtocol", "TLSv1.2")) < 0)
    {
        printf(
            "Setting MinProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MaxProtocol", "TLSv1.3")) < 0)
    {
        printf(
            "Setting MaxProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "CipherString", cipher_list_tlsv12_below)) < 0)
    {
        printf(
            "Setting CipherString for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "Ciphersuites", cipher_list_tlsv13)) < 0)
    {
        printf(
            "Setting Ciphersuites for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "Curves", supported_curves)) < 0)
    {
        printf(
            "Setting Curves for ssl context configuration failed with error %d "
            "\n",
            ssl_conf_return_value);
        goto exit;
    }
    if (!SSL_CONF_CTX_finish(ssl_conf_ctx))
    {
        printf("Error finishing ssl context configuration \n");
        goto exit;
    }
    ret = OE_OK;
exit:
    return ret;
}

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int ret = -1;
    unsigned char buffer[200]; // the expected payload to be read from peer is
                               // at maximum of size 200
    int bytes_read = 0;
    do
    {
        int len = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        bytes_read = SSL_read(ssl_session, buffer, (size_t)len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        printf(" %d bytes read from session peer\n", bytes_read);

        // check to see if received payload is expected
        if ((bytes_read != payload_length) ||
            (memcmp(payload, buffer, bytes_read) != 0))
        {
            printf(
                "ERROR: expected reading %lu bytes but only "
                "received %d bytes\n",
                payload_length,
                bytes_read);
            ret = bytes_read;
            goto exit;
        }
        else
        {
            printf(" received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }
    } while (1);

exit:
    return ret;
}

int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    printf("%lu bytes written to session peer\n\n", payload_length);
exit:
    return ret;
}
