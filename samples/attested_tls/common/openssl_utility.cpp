// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openssl_utility.h"
#include <stdio.h>
#include <string.h>

oe_result_t generate_certificate_and_pkey(X509*& cert, EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
    SSL_CTX_set_ecdh_auto(ctx, 1);
    uint8_t* output_cert = nullptr;
    size_t output_cert_size = 0;
    uint8_t* private_key_buf = nullptr;
    size_t private_key_buf_size = 0;
    uint8_t* public_key_buf = nullptr;
    size_t public_key_buf_size = 0;
    const unsigned char* cert_buf_ptr = nullptr;
    BIO* mem = nullptr;

    result = generate_key_pair(
        &public_key_buf,
        &public_key_buf_size,
        &private_key_buf,
        &private_key_buf_size);

    // OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));
    printf("public_key_buf_size:[%ld]\n", public_key_buf_size);
    printf("public key used:\n[%s]", public_key_buf);

    result = oe_generate_attestation_certificate(
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key_buf,
        private_key_buf_size,
        public_key_buf,
        public_key_buf_size,
        &output_cert,
        &output_cert_size);
    // OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    // temporary buffer required as if d2i_x509 call is successful cert_buf_ptr
    // is incremented to the byte following the parsed data. sending
    // cert_buf_ptr as argument will keep output_cert pointer undisturbed.
    cert_buf_ptr = output_cert;

    if ((cert = d2i_X509(nullptr, &cert_buf_ptr, (long)output_cert_size)) ==
        nullptr)
    {
        printf("Failed to convert DER fromat certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buf, -1);
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
    cert_buf_ptr = nullptr;
    BIO_free(mem);
    oe_free_key(private_key_buf, private_key_buf_size, nullptr, 0);
    oe_free_key(public_key_buf, public_key_buf_size, nullptr, 0);
    oe_free_attestation_certificate(output_cert);
    return result;
}

oe_result_t load_ssl_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& cert,
    EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
    if (generate_certificate_and_pkey(cert, pkey) != OE_OK)
    {
        printf("Cannot generate certificate and pkey\n");
        goto exit;
    }
    if (!SSL_CTX_use_certificate(ctx, cert))
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

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int ret = -1;
    unsigned char buf[200];
    int bytes_read = 0;
    do
    {
        int len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl_session, buf, (size_t)len);

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
            (memcmp(payload, buf, bytes_read) != 0))
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

        printf("Verified: the contents of peer payload were expected\n\n");
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

    printf("%lu bytes written to session peer \n\n", payload_length);
exit:
    return ret;
}