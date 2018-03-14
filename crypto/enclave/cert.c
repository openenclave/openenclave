#ifndef BUILD_HOST
#include <openenclave/enclave.h>
#endif
#define MBEDTLS_PEM_PARSE_C
#include <mbedtls/pem.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/enclavelibc.h>
#include <stdio.h>
#include <stdlib.h>

/*
**==============================================================================
**
** Local functions
**
**==============================================================================
*/

/* Allocate and initialize a new MBEDTLS X509 certificate */
static mbedtls_x509_crt* _CrtNew()
{
    mbedtls_x509_crt* crt = NULL;

    /* Allocate memory for the certificate */
    if (!(crt = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt))))
        goto done;

    /* Iniialize the certificate */
    mbedtls_x509_crt_init(crt);

done:
    return crt;
}

/* Free an MBEDTLS X509 certificate */
static void _CrtFree(mbedtls_x509_crt* crt)
{
    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }
}

/* Load an MBEDTLS X509 certificate from PEM data */
static int _CrtLoad(mbedtls_x509_crt* crt, const char* data, size_t* size)
{
    int ret = -1;
    mbedtls_pem_context pem;

    mbedtls_pem_init(&pem);

    if (size)
        *size = 0;

    /* Read the PEM buffer into DER format */
    if (mbedtls_pem_read_buffer(
            &pem,
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----",
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

static int _CrtChainLoad(mbedtls_x509_crt* chain, const char* data)
{
    int ret = -1;

    if (!chain || !data)
        goto done;

    /* For each PEM certificate in the chain */
    while (*data)
    {
        size_t size;

        /* Load the certificate pointed to by data */
        if (_CrtLoad(chain, data, &size) != 0)
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

OE_Result OE_CertLoad(const char* pem, OE_Cert** cert)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_x509_crt* crt = NULL;
    size_t len;

    if (cert)
        *cert = NULL;

    /* Check parameters */
    if (!pem || !cert)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Allocate memory for the certificate */
    if (!(crt = _CrtNew()))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Read the PEM buffer into DER format */
    if (_CrtLoad(crt, pem, &len) != 0)
        goto done;

    *cert = (OE_Cert*)crt;
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
        _CrtFree(crt);

    return result;
}

void OE_CertFree(OE_Cert* cert)
{
    if (cert)
        _CrtFree((mbedtls_x509_crt*)cert);
}

OE_Result OE_CertChainLoad(const char* pem, OE_CertChain** chain)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_x509_crt* crt = NULL;

    if (chain)
        *chain = NULL;

    /* Check parameters */
    if (!pem || !chain)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Allocate memory for the certificate */
    if (!(crt = _CrtNew()))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Read the PEM buffer into DER format */
    if (_CrtChainLoad(crt, pem) != 0)
        goto done;

    *chain = (OE_CertChain*)crt;
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
        _CrtFree(crt);

    return result;
}

void OE_CertChainFree(OE_CertChain* chain)
{
    if (chain)
        _CrtFree((mbedtls_x509_crt*)chain);
}

OE_Result OE_CertVerify(
    OE_Cert* cert,
    OE_CertChain* chain,
    OE_CRL* crl, /* ATTN: placeholder for future feature work */
    OE_VerifyCertError* error)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_x509_crl cacrl;
    uint32_t flags = 0;

    /* Initialize error to NULL for now */
    if (error)
        *error->buf = '\0';

    /* Reject null parameters */
    if (!cert || !chain)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    OE_Memset(&cacrl, 0, sizeof(cacrl));

    /* Verify the certificate */
    if (mbedtls_x509_crt_verify(
            (mbedtls_x509_crt*)cert,
            (mbedtls_x509_crt*)chain,
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
        result = OE_VERIFY_FAILED;
        goto done;
    }

    result = OE_OK;

done:

    return result;
}
