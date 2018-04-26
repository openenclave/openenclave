// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/config.h>
#include <mbedtls/pem.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/pem.h>
#include <openenclave/bits/raise.h>
#include <openenclave/enclave.h>
#include <openenclave/thread.h>
#include "ec.h"
#include "rsa.h"

/*
**==============================================================================
**
** Referent:
**     Define a structure and functions to represent a reference-counted
**     MBEDTLS certificate chain. This type is used by both OE_Cert and
**     OE_CertChain. This allows OE_CertChainGetCert() to avoid making a
**     copy of the certificate by employing reference counting.
**
**==============================================================================
*/

typedef struct _Referent
{
    mbedtls_x509_crt* chain;
    OE_Spinlock spin;
    uint64_t refs;
} Referent;

/* Allocate and initialize a new referent */
OE_INLINE Referent* _ReferentNew(mbedtls_x509_crt* crt)
{
    Referent* referent;

    if (!(referent = (Referent*)mbedtls_calloc(1, sizeof(Referent))))
        return NULL;

    referent->chain = crt;
    referent->spin = OE_SPINLOCK_INITIALIZER;
    referent->refs = 1;

    return referent;
}

/* Increase the reference count */
OE_INLINE void _ReferentAddRef(Referent* referent)
{
    if (referent)
    {
        OE_SpinLock(&referent->spin);
        referent->refs++;
        OE_SpinUnlock(&referent->spin);
    }
}

/* Decrease the reference count and return its new value */
OE_INLINE void _ReferentFree(Referent* referent)
{
    /* Decrement the reference counter */
    OE_SpinLock(&referent->spin);
    uint64_t refs = --referent->refs;
    OE_SpinUnlock(&referent->spin);

    /* If this was the last reference, release the object */
    if (refs == 0)
    {
        /* Release the MBEDTLS certificate */
        mbedtls_x509_crt_free(referent->chain);

        /* Clear the referent memory */
        OE_Memset(referent, 0, sizeof(Referent));

        /* Free the referent structure */
        mbedtls_free(referent);
    }
}

/*
**==============================================================================
**
** CertImpl:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_CERT_MAGIC 0x028ce9294bcb451a

typedef struct _CertImpl
{
    uint64_t magic;

    /* If referent is non-null, points to a certificate within a chain */
    mbedtls_x509_crt* cert;

    /* Pointer to referent if this certificate is part of a chain */
    Referent* referent;
} CertImpl;

OE_STATIC_ASSERT(sizeof(CertImpl) <= sizeof(OE_Cert));

OE_INLINE void _CertImplInit(
    CertImpl* impl, 
    mbedtls_x509_crt* cert,
    Referent* referent)
{
    impl->magic = OE_CERT_MAGIC;
    impl->cert = cert;
    impl->referent = referent;
    _ReferentAddRef(impl->referent);
}

OE_INLINE bool _CertImplValid(const CertImpl* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->cert;
}

OE_INLINE void _CertImplClear(CertImpl* impl)
{
    impl->magic = 0;
    impl->cert = NULL;
    impl->referent = NULL;
}

/*
**==============================================================================
**
** CertChainImpl:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_CERT_CHAIN_MAGIC 0x7d82c57a12af4c70

typedef struct _CertChainImpl
{
    uint64_t magic;

    /* Pointer to reference-counted implementation shared with CertImpl */
    Referent* referent;
} CertChainImpl;

OE_STATIC_ASSERT(sizeof(CertChainImpl) <= sizeof(OE_CertChain));

OE_INLINE OE_Result _CertChainImplInit(
    CertChainImpl* impl, 
    mbedtls_x509_crt* crt)
{
    /* Create a new referent for this certificate */
    if (!(impl->referent = _ReferentNew(crt)))
        return OE_OUT_OF_MEMORY;

    /* Initialize the implementation */
    impl->magic = OE_CERT_CHAIN_MAGIC;
    return OE_OK;
}

OE_INLINE bool _CertChainImplValid(const CertChainImpl* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->referent;
}

OE_INLINE void _CertChainImplClear(CertChainImpl* impl)
{
    impl->magic = 0;
    impl->referent = NULL;
}

/*
**==============================================================================
**
** _SetErr()
**
**==============================================================================
*/

static void _SetErr(OE_VerifyCertError* error, const char* str)
{
    if (error)
        OE_Strlcpy(error->buf, str, sizeof(error->buf));
}

/*
**==============================================================================
**
** _CrtRead()
**     Read an MBEDTLS X509 certificate from PEM data.
**
**==============================================================================
*/

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

/*
**==============================================================================
**
** _CrtChainRead()
**     Read an MBEDTLS X509 certificate chain from PEM data.
**
**==============================================================================
*/

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
    CertImpl* impl = (CertImpl*)cert;
    mbedtls_x509_crt* crt = NULL;
    size_t len;

    /* Clear the implementation */
    if (impl)
        _CertImplClear(impl);

    /* Check parameters */
    if (!pemData || !pemSize || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate memory for the certificate */
    if (!(crt = mbedtls_calloc(1, sizeof(mbedtls_x509_crt))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the certificate struture */
    mbedtls_x509_crt_init(crt);

    /* Read the PEM buffer into DER format */
    if (_CrtRead(crt, (const char*)pemData, &len) != 0)
        OE_RAISE(OE_FAILURE);

    /* Initialize the implementation */
    _CertImplInit(impl, crt, NULL);
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        mbedtls_free(crt);
    }

    return result;
}

OE_Result OE_CertFree(OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    CertImpl* impl = (CertImpl*)cert;

    /* Check the parameter */
    if (!_CertImplValid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the referent if its reference count is one */
    if (impl->referent)
        _ReferentFree(impl->referent);

    /* Free the certificate */
    mbedtls_x509_crt_free(impl->cert);
    mbedtls_free(impl->cert);
    _CertImplClear(impl);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_CertChainReadPEM(
    const void* pemData,
    size_t pemSize,
    OE_CertChain* chain)
{
    OE_Result result = OE_UNEXPECTED;
    CertChainImpl* impl = (CertChainImpl*)chain;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the implementation (making it invalid) */
    if (impl)
        OE_Memset(impl, 0, sizeof(CertChainImpl));

    /* Check parameters */
    if (!pemData || !pemSize || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate memory for the certificate */
    if (!(crt = mbedtls_calloc(1, sizeof(mbedtls_x509_crt))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the MBEDTLS certificate */
    mbedtls_x509_crt_init(crt);

    /* Read the PEM buffer into DER format */
    if (_CrtChainRead(crt, (const char*)pemData) != 0)
        OE_RAISE(OE_FAILURE);

    /* Initialize the implementation */
    OE_CHECK(_CertChainImplInit(impl, crt));
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        mbedtls_free(crt);
    }

    return result;
}

OE_Result OE_CertChainFree(OE_CertChain* chain)
{
    OE_Result result = OE_UNEXPECTED;
    CertChainImpl* impl = (CertChainImpl*)chain;

    /* Check the parameter */
    if (!_CertChainImplValid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the referent if the reference count is one */
    _ReferentFree(impl->referent);

    /* Clear the implementation (making it invalid) */
    _CertChainImplClear(impl);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_CertVerify(
    OE_Cert* cert,
    OE_CertChain* chain,
    OE_CRL* crl, /* ATTN: placeholder (future feature work) */
    OE_VerifyCertError* error)
{
    OE_Result result = OE_UNEXPECTED;
    CertImpl* certImpl = (CertImpl*)cert;
    CertChainImpl* chainImpl = (CertChainImpl*)chain;
    uint32_t flags = 0;

    /* Initialize error */
    if (error)
        *error->buf = '\0';

    /* Reject invalid certificate */
    if (!_CertImplValid(certImpl))
    {
        _SetErr(error, "invalid cert parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject invalid certificate chain */
    if (!_CertChainImplValid(chainImpl))
    {
        _SetErr(error, "invalid chain parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Verify the certificate */
    if (mbedtls_x509_crt_verify(
            certImpl->cert,
            chainImpl->referent->chain,
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

        OE_RAISE(OE_VERIFY_FAILED);
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_CertGetRSAPublicKey(
    const OE_Cert* cert,
    OE_RSAPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    const CertImpl* impl = (const CertImpl*)cert;
    OE_RSAPublicKeyImpl* publicKeyImpl = (OE_RSAPublicKeyImpl*)publicKey;

    /* Clear public key for all error pathways */
    if (publicKey)
        OE_Memset(publicKey, 0, sizeof(OE_RSAPublicKey));

    /* Reject invalid parameters */
    if (!_CertImplValid(impl) || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Copy the public key from the certificate */
    if (OE_RSACopyKey(&publicKeyImpl->pk, &impl->cert->pk, false) != 0)
        OE_RAISE(OE_FAILURE);

    /* Set the magic number */
    publicKeyImpl->magic = OE_RSA_PUBLIC_KEY_MAGIC;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_CertGetECPublicKey(const OE_Cert* cert, OE_ECPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    const CertImpl* impl = (const CertImpl*)cert;
    OE_ECPublicKeyImpl* publicKeyImpl = (OE_ECPublicKeyImpl*)publicKey;

    /* Clear public key for all error pathways */
    if (publicKey)
        OE_Memset(publicKey, 0, sizeof(OE_ECPublicKey));

    /* Reject invalid parameters */
    if (!_CertImplValid(impl) || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Copy the public key from the certificate */
    if (OE_ECCopyKey(&publicKeyImpl->pk, &impl->cert->pk, false) != 0)
        OE_RAISE(OE_FAILURE);

    /* Set the magic number */
    publicKeyImpl->magic = OE_EC_PUBLIC_KEY_MAGIC;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_CertChainGetLength(const OE_CertChain* chain, uint32_t* length)
{
    OE_Result result = OE_UNEXPECTED;
    const CertChainImpl* impl = (const CertChainImpl*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_CertChainImplValid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Count the certificates in the chain */
    {
        uint32_t n = 0;

        for (const mbedtls_x509_crt* p = impl->referent->chain; p; p = p->next)
            n++;

        *length = n;
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_CertChainGetCert(
    const OE_CertChain* chain,
    uint32_t index,
    OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    CertChainImpl* impl = (CertChainImpl*)chain;
    CertImpl* certImpl = (CertImpl*)cert;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        OE_Memset(cert, 0, sizeof(OE_Cert));

    /* Reject invalid parameters */
    if (!_CertChainImplValid(impl) || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the certificate with this index */
    {
        size_t i = 0;

        for (mbedtls_x509_crt *p = impl->referent->chain; p; p = p->next, i++)
        {
            if (i == index)
            {
                crt = p;
                break;
            }

            if (index == OE_MAX_UINT32 && !p->next)
            {
                crt = p;
                break;
            }
        }

        if (!crt)
            OE_RAISE(OE_OUT_OF_BOUNDS);
    }

    /* Initialize the implementation */
    _CertImplInit(certImpl, crt, impl->referent);

done:

    return result;
}
