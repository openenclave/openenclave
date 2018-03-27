// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/config.h>
#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/pem.h>
#include <openenclave/bits/trace.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include "../util.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

typedef struct _OE_CertImpl
{
    uint64_t magic;
    mbedtls_x509_crt cert;
} OE_CertImpl;

OE_STATIC_ASSERT(sizeof(OE_CertImpl) < sizeof(OE_Cert));

#define OE_CERT_MAGIC 0x882b9943ac1ca95d

static bool _ValidCertImpl(const OE_CertImpl* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC);
}

#define OE_CERT_CHAIN_MAGIC 0xe863a8d48452376a

typedef struct _OE_CertChainImpl
{
    uint64_t magic;
    mbedtls_x509_crt chain;
} OE_CertChainImpl;

OE_STATIC_ASSERT(sizeof(OE_CertChainImpl) < sizeof(OE_CertChain));

static bool _ValidCertChainImpl(const OE_CertChainImpl* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC);
}

/* Read an MBEDTLS X509 certificate from PEM data */
static int _CrtRead(mbedtls_x509_crt* crt, const char* data, size_t* size)
{
    int ret = -1;
    mbedtls_pem_context pem;

    mbedtls_pem_init(&pem);

    if (size)
        *size = 0;

    /* Read the PEM buffer into DER format */
    if (mbedtls_pem_read_buffer(
            &pem,
            OE_PEM_BEGIN_CERTIFICATE,
            OE_PEM_END_CERTIFICATE,
            (unsigned char*)data,
            NULL, /* pwd */
            0,    /* pwdlen */
            size) != 0)
    {
        goto done;
    }

    /* Parse the DER format and add a new certificate to the chain */
    if (mbedtls_x509_crt_parse_der(crt, pem.buf, pem.buflen) != 0)
        goto done;

    ret = 0;

done:

    mbedtls_pem_free(&pem);

    return ret;
}

static int _CrtChainRead(mbedtls_x509_crt* chain, const char* data)
{
    int ret = -1;

    if (!chain || !data)
        goto done;

    /* For each PEM certificate in the chain */
    while (*data)
    {
        size_t size;

        /* Read the certificate pointed to by data */
        if (_CrtRead(chain, data, &size) != 0)
            goto done;

        /* Skip to next certificate (if any) */
        data += size;
    }

    ret = 0;

done:

    return ret;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

OE_Result OE_CertReadPEM(const void* pemData, size_t pemSize, OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertImpl* impl = (OE_CertImpl*)cert;
    size_t len;

    /* Clear the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pemData || !pemSize || !cert)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the implementation */
    mbedtls_x509_crt_init(&impl->cert);
    impl->magic = OE_CERT_MAGIC;

    /* Read the PEM buffer into DER format */
    if (_CrtRead(&impl->cert, (const char*)pemData, &len) != 0)
        OE_THROW(OE_FAILURE);

    OE_THROW(OE_OK);

OE_CATCH:

    if (result != OE_OK && impl->magic == OE_CERT_MAGIC)
    {
        mbedtls_x509_crt_free(&impl->cert);
        impl->magic = 0;
    }

    return result;
}

OE_Result OE_CertFree(OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertImpl* impl = (OE_CertImpl*)cert;

    /* Check the parameter */
    if (!_ValidCertImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Free the certificate */
    mbedtls_x509_crt_free(&impl->cert);
    impl->magic = 0;

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

OE_Result OE_CertChainReadPEM(
    const void* pemData,
    size_t pemSize,
    OE_CertChain* chain)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertChainImpl* impl = (OE_CertChainImpl*)chain;

    /* Clear the implementation */
    if (impl)
        impl->magic = 0;

    /* Check parameters */
    if (!pemData || !pemSize || !chain)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the implementation */
    mbedtls_x509_crt_init(&impl->chain);
    impl->magic = OE_CERT_CHAIN_MAGIC;

    /* Read the PEM buffer into DER format */
    if (_CrtChainRead(&impl->chain, (const char*)pemData) != 0)
        OE_THROW(OE_FAILURE);

    OE_THROW(OE_OK);

OE_CATCH:

    if (result != OE_OK && impl->magic == OE_CERT_MAGIC)
    {
        mbedtls_x509_crt_free(&impl->chain);
        impl->magic = 0;
    }

    return result;
}

OE_Result OE_CertChainFree(OE_CertChain* chain)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertChainImpl* impl = (OE_CertChainImpl*)chain;

    /* Check the parameter */
    if (!_ValidCertChainImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Free the certificate */
    mbedtls_x509_crt_free(&impl->chain);
    impl->magic = 0;

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

OE_Result OE_CertVerify(
    OE_Cert* cert,
    OE_CertChain* chain,
    OE_CRL* crl, /* ATTN: placeholder (future feature work) */
    OE_VerifyCertError* error)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CertImpl* certImpl = (OE_CertImpl*)cert;
    OE_CertChainImpl* chainImpl = (OE_CertChainImpl*)chain;
    uint32_t flags = 0;

    /* Initialize error */
    if (error)
        *error->buf = '\0';

    /* Reject null parameters */
    if (!_ValidCertImpl(certImpl) || !_ValidCertChainImpl(chainImpl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Verify the certificate */
    if (mbedtls_x509_crt_verify(
            &certImpl->cert,
            &chainImpl->chain,
            NULL,
            NULL,
            &flags,
            NULL,
            NULL) != 0)
    {
        if (error)
        {
            mbedtls_x509_crt_verify_info(
                error->buf, sizeof(error->buf), "", flags);
        }

        OE_THROW(OE_VERIFY_FAILED);
    }

    OE_THROW(OE_OK);

OE_CATCH:

    return result;
}
