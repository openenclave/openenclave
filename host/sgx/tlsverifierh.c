// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/utils.h>
#include "../common/common.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// verify report data against peer certificate
oe_result_t verify_report_user_data(
    uint8_t* key_buff,
    size_t key_buff_size,
    uint8_t* report_data);
oe_result_t get_public_key_from_cert(
    X509* cert,
    uint8_t* key_buff,
    size_t* key_size);
// oe_result_t verify_cert(X509 *cert);
oe_result_t verify_cert_signature(X509* cert);

static unsigned char oid_oe_report[] =
    {0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x01};
// static unsigned char *quote_ext_oid = "1.2.840.113741.1337.1";

// static char *quote_ext_oid = "1.2.840.113741.1337.1";

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed because some versions of OpenSSL do not support X509_up_ref() */
static const STACK_OF(X509_EXTENSION) * X509_get0_extensions(const X509* x)
{
    if (!x->cert_info)
    {
        return NULL;
    }
    return x->cert_info->extensions;
}

#endif

// Extract extensions from X509 and decode base64
static oe_result_t get_extension(
    const X509* crt,          /* in */
    const unsigned char* oid, /* in */
    int oid_len,              /* in */
    uint8_t** data,           /* out */
    size_t* data_len          /* out */
)
{
    oe_result_t result = OE_NOT_FOUND;
    const STACK_OF(X509_EXTENSION)* exts = NULL;
    int extension_count = 0;
    int bytes_count = 0;
    (void)oid;
    exts = X509_get0_extensions(crt);
    if (exts == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);
    /*
        for (int i=0; i < num_of_exts; i++) {
            X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
            assert(ex != NULL);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
            assert(obj != NULL);

            if (oid_len != obj->length) continue;

            if (0 == memcmp(obj->data, oid, obj->length)) {
                *data = ex->value->data;
                *data_len = ex->value->length;
                break;
            }
        }
    */
    /*
            OBJ_obj2txt(s, sizeof(s), X509_EXTENSION_get_object(ex), 1);
            printf("%d OID=%s\n", i, s);

            asnobject = X509_EXTENSION_get_object(ex);
            asndata = X509_EXTENSION_get_data(ex);

            p1 = ASN1_STRING_data(asndata);
            p = p1;
            length1 = ASN1_STRING_length(asndata);
    */
    extension_count = sk_X509_EXTENSION_num(exts);
    for (int i = 0; i < extension_count; i++)
    {
        X509_EXTENSION* ex = NULL;
        char buff[128];

        ex = sk_X509_EXTENSION_value(exts, i);
        if (ex == NULL)
        {
            goto done;
        }

        bytes_count =
            OBJ_obj2txt(buff, sizeof(buff), X509_EXTENSION_get_object(ex), 1);
        OE_TRACE_INFO("ext(%d) bytes_count = %d\n", i, bytes_count);

        // bytes_count = i2t_ASN1_OBJECT(buff, sizeof(buff),
        // X509_EXTENSION_get_object(ex));

        // bytes_count = i2t_ASN1_OBJECT(buff, sizeof(buff),
        // X509_EXTENSION_get_object(ex));
        if ((bytes_count == 0) && (oid_len != bytes_count))
        {
            OE_TRACE_ERROR(
                "Unexpected bytes_count (%d) oid_len = %d",
                bytes_count,
                oid_len);
            goto done;
        }
        OE_TRACE_INFO("buff=[%s]\n", buff);

        /* If found matching oid then get the data */
        // if (memcmp(buff, oid, (size_t)bytes_count) == 0)
        // [1.2.840.113741.1337.1]
        if (memcmp("1.2.840.113741.1337.1", buff, strlen(buff)) == 0)
        {
            ASN1_OCTET_STRING* str;

            /* Get the data from the extension */
            if (!(str = X509_EXTENSION_get_data(ex)))
                OE_RAISE(OE_FAILURE);

            /* If the caller's buffer is too small, raise error */
            // if ((size_t)str->length > *data_len)
            // {
            //     *data_len = (size_t)str->length;
            //     OE_RAISE(OE_BUFFER_TOO_SMALL);
            // }

            if (data)
            {
                *data = (uint8_t*)(str->data);
                *data_len = (size_t)str->length;
                result = OE_OK;
                goto done;
            }
        }
    }
done:
    return result;
}

static oe_result_t extract_x509_report_extension(
    const X509* crt,
    uint8_t** ext_data,
    size_t* ext_data_size)
{
    oe_result_t result = OE_FAILURE;

    result = get_extension(
        crt, oid_oe_report, sizeof(oid_oe_report), ext_data, ext_data_size);
    OE_CHECK(result);

    if (*ext_data_size != 0)
        result = OE_OK;

done:
    return result;
}

oe_result_t verify_cert_signature(X509* cert)
{
    (void)cert;

    //     oe_result_t result = OE_VERIFY_FAILED;
    //     X509_STORE_CTX* ctx = NULL;

    //     /* Create a context for verification */
    //     if (!(ctx = X509_STORE_CTX_new()))
    //         OE_RAISE(OE_FAILURE);

    //     /* Initialize the context that will be used to verify the certificate
    //     */ if (!X509_STORE_CTX_init(ctx, NULL, NULL, NULL))
    //         OE_RAISE(OE_FAILURE);

    //     /* Inject the certificate into the verification context */
    //     X509_STORE_CTX_set_cert(ctx, cert);

    //     /* Set the CA chain into the verification context */
    //     //X509_STORE_CTX_trusted_stack(ctx, chain);

    //     /* Finally verify the certificate */
    //     if (!X509_verify_cert(ctx))
    //         OE_RAISE_MSG(OE_FAILURE, "certificate signature validation
    //         failed!");

    //     result = OE_OK;
    // done:
    //     if (ctx)
    //         X509_STORE_CTX_free(ctx);

    //     return result;

    return OE_OK;
}
/*
// verify report data against peer certificate
oe_result_t verify_report_user_data(mbedtls_x509_crt* cert, uint8_t*
report_data)
{
    oe_result_t result = OE_FAILURE;
    int ret = 0;
    uint8_t pk_buf[OE_RSA_KEY_BUFF_SIZE];
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256;

    oe_memset_s(pk_buf, sizeof(pk_buf), 0, sizeof(pk_buf));
    ret  = mbedtls_pk_write_pubkey_pem(&cert->pk, pk_buf, sizeof(pk_buf));
    if (ret)
        OE_RAISE_MSG(OE_FAILURE, "ret = %d", ret);

    OE_TRACE_INFO("pk_buf=[%s]",pk_buf);
    OE_TRACE_INFO("oe_strlen(pk_buf)=[%d]",oe_strlen((const char *)pk_buf));

    OE_TRACE_VERBOSE("public key from the peer certificate =\n[%s]", pk_buf);
    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, pk_buf, oe_strlen((const char
*)pk_buf)+1)); // +1 for the ending null char
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    // validate report's user data, which contains hash(public key)
    if (memcmp(report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) != 0)
    {
        for (int i=0; i<OE_SHA256_SIZE; i++)
            OE_TRACE_VERBOSE("[%d] report_data[0x%x] sha256=0x%x ", i,
report_data[i], sha256.buf[i]); OE_RAISE_MSG(OE_VERIFY_FAILED, "hash of peer
certificate's public key does not match report data", NULL);
    }

    OE_TRACE_INFO("Report user data validation passed");
    result = OE_OK;
done:
    return result;
}
*/
oe_result_t verify_report_user_data(
    uint8_t* key_buff,
    size_t key_buff_size,
    uint8_t* report_data)
{
    oe_result_t result = OE_FAILURE;
    OE_SHA256 sha256;
    oe_sha256_context_t sha256_ctx = {0};

    OE_TRACE_INFO("key_buff_size = %ld", key_buff_size);

    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(
        &sha256_ctx, key_buff, oe_strlen((const char*)key_buff) + 1));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    if (memcmp(report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) != 0)
    {
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "hash of peer certificate's public key does not match report data",
            NULL);
    }
    OE_TRACE_INFO("report data validation passed", NULL);

    result = OE_OK;
done:
    return result;
}
oe_result_t get_public_key_from_cert(
    X509* cert,
    uint8_t* key_buff,
    size_t* key_size)
{
    oe_result_t result = OE_FAILURE;
    EVP_PKEY* pkey = NULL;
    BIO* bio_mem = BIO_new(BIO_s_mem());
    int bio_len = 0;
    int ret = 0;

    // Extract the certificate's public key
    if ((pkey = X509_get_pubkey(cert)) == NULL)
        OE_RAISE(result, "Error getting public key from certificate", NULL);

    OE_TRACE_INFO("extract_x509_report_extension() succeeded");

    /* ---------------------------------------------------------- *
     * Print the public key information and the key in PEM format *
     * ---------------------------------------------------------- */
    // display the key type and size  in PEM format
    if (pkey)
    {
        switch (EVP_PKEY_id(pkey))
        {
            case EVP_PKEY_RSA:
                OE_TRACE_INFO("%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
                break;
            case EVP_PKEY_DSA:
                OE_TRACE_INFO("%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
                break;
            default:
                OE_TRACE_INFO(
                    "%d bit  non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
                break;
        }
    }

    if (!PEM_write_bio_PUBKEY(bio_mem, pkey))
        OE_RAISE(
            OE_FAILURE, "Error writing public key data in PEM format", NULL);

    bio_len = BIO_pending(bio_mem);
    ret = BIO_read(bio_mem, key_buff, bio_len);
    if (ret != bio_len)
    {
        // that no data was successfully read or written if the result is 0 or
        // -1. If the return value is -2 then the operation is not implemented
        // in the specific BIO type.
        OE_RAISE(result, "BIO_read key data failed ret = %d", ret);
    }
    // Insert the NUL terminator
    key_buff[bio_len] = '\0';

    OE_TRACE_INFO("public key from cert:\n[%s]\n", key_buff);
    *key_size = (size_t)bio_len;
    result = OE_OK;
done:
    BIO_free_all(bio_mem);
    EVP_PKEY_free(pkey);

    return result;
}

oe_result_t oe_verify_tls_cert(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_enclave_identity_verify_callback_t enclave_identity_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    const unsigned char* p = cert_in_der;
    X509* cert = NULL;
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t pub_key_buf[OE_RSA_KEY_BUFF_SIZE];
    size_t pub_key_buf_size = 0;
    oe_report_t parsed_report = {0};

    //  OpenSSL_add_all_algorithms();
    //   ERR_load_BIO_strings();
    //   ERR_load_crypto_strings();

    // create a OpenSSL cert object from encoded cert data in DER format
    cert = d2i_X509(NULL, &p, (uint32_t)cert_in_der_len);
    if (cert == NULL)
        OE_RAISE(
            result,
            "d2i_X509 failed err=[%s]",
            ERR_error_string(ERR_get_error(), NULL));

    // validate the certificate signature
    result = verify_cert_signature(cert);
    OE_CHECK(result);

    //------------------------------------------------------------------------
    // Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now
    //------------------------------------------------------------------------
    result = extract_x509_report_extension(cert, &report, &report_size);
    OE_CHECK(result);
    OE_TRACE_INFO("extract_x509_report_extension() succeeded");

    result = oe_verify_report(NULL, report, report_size, &parsed_report);
    OE_CHECK(result);
    OE_TRACE_INFO("oe_verify_report() succeeded");

    //--------------------------------------
    // verify report data: hash(public key)
    //--------------------------------------

    // extract public key from the cert
    oe_memset_s(pub_key_buf, sizeof(pub_key_buf), 0, sizeof(pub_key_buf));
    result = get_public_key_from_cert(cert, pub_key_buf, &pub_key_buf_size);
    OE_CHECK(result);

    // verify report data against peer certificate
    result = verify_report_user_data(
        pub_key_buf, pub_key_buf_size, parsed_report.report_data);
    OE_CHECK(result);
    OE_TRACE_INFO("verify_report_user_data passed", NULL);

    //---------------------------------------
    // call client to check enclave identity
    // --------------------------------------
    if (enclave_identity_callback)
    {
        result = enclave_identity_callback(&parsed_report.identity, arg);
        OE_CHECK(result);
        OE_TRACE_INFO("enclave_identity_callback() succeeded");
    }
    else
    {
        OE_TRACE_WARNING(
            "No enclave_identity_callback provided in oe_verify_tls_cert call",
            NULL);
    }

done:
    if (cert)
        X509_free(cert);

    return result;
}
