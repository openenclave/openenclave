// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openssl_utility.h"
#include <stdio.h>
#include <string.h>
#include "tls_e2e_t.h"

extern struct tls_control_args g_control_config;

oe_result_t generate_certificate_and_pkey(X509*& cert, EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
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

    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));
    OE_TRACE_INFO("public_key_buf_size:[%ld]\n", public_key_buf_size);
    OE_TRACE_INFO("public key used:\n[%s]", public_key_buf);

    result = oe_generate_attestation_certificate(
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key_buf,
        private_key_buf_size,
        public_key_buf,
        public_key_buf_size,
        &output_cert,
        &output_cert_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    // temporary buffer required as if d2i_x509 call is successful cert_buf_ptr
    // is incremented to the byte following the parsed data. sending
    // cert_buf_ptr as argument will keep output_cert pointer undisturbed.
    cert_buf_ptr = output_cert;

    if ((cert = d2i_X509(nullptr, &cert_buf_ptr, (long)output_cert_size)) ==
        nullptr)
    {
        OE_TRACE_ERROR(
            TLS_SERVER
            "Failed to convert DER fromat certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buf, -1);
    if (!mem)
    {
        OE_TRACE_ERROR(TLS_SERVER
                       "Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        OE_TRACE_ERROR(
            TLS_SERVER
            "Failed to convert private key buffer into EVP_KEY format\n");
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

// The return value of verify_callback controls the strategy of the further
// verification process. If verify_callback returns 0, the verification process
// is immediately stopped with "verification failed" state and a verification
// failure alert is sent to the peer and the TLS/SSL handshake is terminated. If
// verify_callback returns 1, the verification process is continued.
int cert_verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    int ret = 0;
    size_t der_len = 0;
    unsigned char* der = nullptr;
    unsigned char* buf = nullptr;
    oe_result_t result = OE_FAILURE;
    X509* crt = nullptr;
    int err = X509_V_ERR_UNSPECIFIED;

    if (g_control_config.fail_cert_verify_callback)
    {
        OE_TRACE_INFO(
            "Purposely returns failure from server's cert_verify_callback()\n");
        goto done;
    }

    OE_TRACE_INFO(
        TLS_SERVER "verify_callback called with preverify_ok=%d\n",
        preverify_ok);
    crt = X509_STORE_CTX_get_current_cert(ctx);
    if (crt == nullptr)
    {
        OE_TRACE_ERROR(TLS_SERVER "failed to retrieve certificate\n");
        goto done;
    }

    if (preverify_ok == 0)
    {
        err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        {
            // A self-signed certificate is expected, return 1 to continue the
            // verification process. if the generated certificate is a
            // self-signed one, we are catching that error and sending return
            // value as 1, which keeps preverify_ok = 1 and further certificate
            // verification is done in the next call. In total,
            // cert_verify_callback would be called twice once with preverify_ok
            // = 0 and second time with preverify_ok=1
            OE_TRACE_INFO(TLS_SERVER "self-signed certificated detected\n");
            ret = 1;
            goto done;
        }
    }

    // convert a cert into a buffer in DER format
    der_len = (size_t)i2d_X509(crt, nullptr);
    buf = (unsigned char*)malloc(der_len);
    if (buf == nullptr)
    {
        OE_TRACE_ERROR(TLS_SERVER "malloc failed (der_len=%d)\n", der_len);
        goto done;
    }
    der = buf;
    der_len = (size_t)i2d_X509(crt, &buf);
    if (der_len < 0)
    {
        OE_TRACE_ERROR(TLS_SERVER "i2d_X509 failed(der_len=%d)\n", der_len);
        goto done;
    }

    if (g_control_config.fail_oe_verify_attestation_certificate)
        goto done;
    // verify tls certificate
    result = oe_verify_attestation_certificate(
        der, der_len, enclave_identity_verifier, nullptr);

    if (result != OE_OK)
    {
        OE_TRACE_ERROR(TLS_SERVER "result=%s\n", oe_result_str(result));
        goto done;
    }
    ret = 1;
done:

    if (der)
        free(der);

    if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
    {
        OE_TRACE_ERROR(
            TLS_SERVER "verifying SGX certificate extensions ... %s\n",
            ret ? "succeeded" : "failed");
    }
    return ret;
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
        bytes_read = SSL_read(ssl_session, buf, len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            OE_TRACE_ERROR("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        OE_TRACE_INFO(" %d bytes read from session peer\n", bytes_read);

        // check to see if received payload is expected
        if ((bytes_read != (int)payload_length) ||
            (memcmp(payload, buf, (size_t)bytes_read) != 0))
        {
            OE_TRACE_ERROR(
                "ERROR: expected reading %lu bytes but only "
                "received %d bytes\n",
                payload_length,
                bytes_read);
            ret = bytes_read;
            goto exit;
        }
        else
        {
            OE_TRACE_INFO(
                " received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }

        OE_TRACE_INFO(
            "Verified: the contents of peer payload were expected\n\n");
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

    while ((bytes_written =
                SSL_write(ssl_session, payload, (int)payload_length)) <= 0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        OE_TRACE_INFO("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    OE_TRACE_INFO("%lu bytes written to session peer \n\n", payload_length);
exit:
    return ret;
}

oe_result_t initalize_ssl_context(SSL_CTX*& ctx)
{
    oe_result_t ret = OE_FAILURE;
    // choose TLSv1.2 by excluding SSLv2, SSLv3 ,TLS 1.0 and TLS 1.1
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &cert_verify_callback);
    ret = OE_OK;
    return ret;
}

oe_result_t load_ssl_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& cert,
    EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
    if (generate_certificate_and_pkey(cert, pkey) != OE_OK)
    {
        OE_TRACE_ERROR(TLS_SERVER "Cannot generate certificate and pkey\n");
        goto exit;
    }
    if (!SSL_CTX_use_certificate(ctx, cert))
    {
        OE_TRACE_ERROR(TLS_SERVER "Cannot load certificate on the server\n");
        goto exit;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
    {
        OE_TRACE_ERROR(TLS_SERVER "Cannot load private key on the server\n");
        goto exit;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        OE_TRACE_ERROR(TLS_SERVER
                       "Private key does not match the public certificate\n");
        goto exit;
    }
    result = OE_OK;
exit:
    return result;
}
