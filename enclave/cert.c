// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/asn1.h>
#include <mbedtls/config.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/bits/atomic.h>
#include <openenclave/bits/cert.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/pem.h>
#include <openenclave/bits/raise.h>
#include <openenclave/enclave.h>
#include <openenclave/thread.h>
#include "ec.h"
#include "pem.h"
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
    /* The first certificate in the chain (crt->next points to the next) */
    mbedtls_x509_crt crt;

    /* The length of the certificate chain */
    size_t length;

    /* Reference count */
    volatile uint64_t refs;
} Referent;

/* Allocate and initialize a new referent */
OE_INLINE Referent* _ReferentNew(void)
{
    Referent* referent;

    if (!(referent = (Referent*)mbedtls_calloc(1, sizeof(Referent))))
        return NULL;

    mbedtls_x509_crt_init(&referent->crt);
    referent->length = 0;
    referent->refs = 1;

    return referent;
}

OE_INLINE mbedtls_x509_crt* _ReferentGetCert(Referent* referent, size_t index)
{
    size_t i = 0;

    for (mbedtls_x509_crt *p = &referent->crt; p; p = p->next, i++)
    {
        if (i == index)
            return p;
    }

    /* Out of bounds */
    return NULL;
}

/* Increase the reference count */
OE_INLINE void _ReferentAddRef(Referent* referent)
{
    if (referent)
        OE_AtomicIncrement(&referent->refs);
}

/* Decrease the reference count and return its new value */
OE_INLINE void _ReferentFree(Referent* referent)
{
    /* If this was the last reference, release the object */
    if (OE_AtomicDecrement(&referent->refs) == 0)
    {
        /* Release the MBEDTLS certificate */
        mbedtls_x509_crt_free(&referent->crt);

        /* Free the referent structure */
        OE_Memset(referent, 0, sizeof(Referent));
        mbedtls_free(referent);
    }
}

/*
**==============================================================================
**
** Cert:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_CERT_MAGIC 0x028ce9294bcb451a

typedef struct _Cert
{
    uint64_t magic;

    /* If referent is non-null, points to a certificate within a chain */
    mbedtls_x509_crt* cert;

    /* Pointer to referent if this certificate is part of a chain */
    Referent* referent;
} Cert;

OE_STATIC_ASSERT(sizeof(Cert) <= sizeof(OE_Cert));

OE_INLINE void _CertInit(Cert* impl, mbedtls_x509_crt* cert, Referent* referent)
{
    impl->magic = OE_CERT_MAGIC;
    impl->cert = cert;
    impl->referent = referent;
    _ReferentAddRef(impl->referent);
}

OE_INLINE bool _CertValid(const Cert* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->cert;
}

OE_INLINE void _CertFree(Cert* impl)
{
    /* Release the referent if its reference count is one */
    if (impl->referent)
    {
        /* impl->cert == &impl->referent->crt */
        _ReferentFree(impl->referent);
    }
    else
    {
        /* Release the MBEDTLS certificate */
        mbedtls_x509_crt_free(impl->cert);
        OE_Memset(impl->cert, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(impl->cert);
    }

    /* Clear the fields */
    OE_Memset(impl, 0, sizeof(Cert));
}

/*
**==============================================================================
**
** CertChain:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_CERT_CHAIN_MAGIC 0x7d82c57a12af4c70

typedef struct _CertChain
{
    uint64_t magic;

    /* Pointer to reference-counted implementation shared with Cert */
    Referent* referent;
} CertChain;

OE_STATIC_ASSERT(sizeof(CertChain) <= sizeof(OE_CertChain));

OE_INLINE OE_Result _CertChainInit(CertChain* impl, Referent* referent)
{
    impl->magic = OE_CERT_CHAIN_MAGIC;
    impl->referent = referent;
    _ReferentAddRef(referent);
    return OE_OK;
}

OE_INLINE bool _CertChainValid(const CertChain* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->referent;
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
** Public functions
**
**==============================================================================
*/

OE_Result OE_CertReadPEM(const void* pemData, size_t pemSize, OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the implementation */
    if (impl)
        OE_Memset(impl, 0, sizeof(Cert));

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
    if (mbedtls_x509_crt_parse(crt, (const uint8_t*)pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Initialize the implementation */
    _CertInit(impl, crt, NULL);
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        OE_Memset(crt, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(crt);
    }

    return result;
}

OE_Result OE_CertFree(OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;

    /* Check the parameter */
    if (!_CertValid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    _CertFree(impl);

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
    CertChain* impl = (CertChain*)chain;
    Referent* referent = NULL;

    /* Clear the implementation (making it invalid) */
    if (impl)
        OE_Memset(impl, 0, sizeof(CertChain));

    /* Check parameters */
    if (!pemData || !pemSize || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create the referent */
    if (!(referent = _ReferentNew()))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Read the PEM buffer into DER format */
    if (mbedtls_x509_crt_parse(
            &referent->crt, (const uint8_t*)pemData, pemSize) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Calculate the length of the certificate chain */
    for (mbedtls_x509_crt* p = &referent->crt; p; p = p->next)
        referent->length++;

    /* Initialize the implementation and increment reference count */
    OE_CHECK(_CertChainInit(impl, referent));

    result = OE_OK;

done:

    _ReferentFree(referent);

    return result;
}

OE_Result OE_CertChainFree(OE_CertChain* chain)
{
    OE_Result result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;

    /* Check the parameter */
    if (!_CertChainValid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the referent if the reference count is one */
    _ReferentFree(impl->referent);

    /* Clear the implementation (making it invalid) */
    OE_Memset(impl, 0, sizeof(CertChain));

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
    Cert* certImpl = (Cert*)cert;
    CertChain* chainImpl = (CertChain*)chain;
    uint32_t flags = 0;

    /* Initialize error */
    if (error)
        *error->buf = '\0';

    /* Reject invalid certificate */
    if (!_CertValid(certImpl))
    {
        _SetErr(error, "invalid cert parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject invalid certificate chain */
    if (!_CertChainValid(chainImpl))
    {
        _SetErr(error, "invalid chain parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Verify the certificate */
    if (mbedtls_x509_crt_verify(
            certImpl->cert,
            &chainImpl->referent->crt,
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
    const Cert* impl = (const Cert*)cert;
    OE_RSAPublicKeyImpl* publicKeyImpl = (OE_RSAPublicKeyImpl*)publicKey;

    /* Clear public key for all error pathways */
    if (publicKey)
        OE_Memset(publicKey, 0, sizeof(OE_RSAPublicKey));

    /* Reject invalid parameters */
    if (!_CertValid(impl) || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If certificate does not contain an RSA key */
    if (!OE_IsRSAKey(&impl->cert->pk))
        OE_RAISE(OE_FAILURE);

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
    const Cert* impl = (const Cert*)cert;
    OE_ECPublicKeyImpl* publicKeyImpl = (OE_ECPublicKeyImpl*)publicKey;

    /* Clear public key for all error pathways */
    if (publicKey)
        OE_Memset(publicKey, 0, sizeof(OE_ECPublicKey));

    /* Reject invalid parameters */
    if (!_CertValid(impl) || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If certificate does not contain an EC key */
    if (!OE_IsECKey(&impl->cert->pk))
        OE_RAISE(OE_FAILURE);

    /* Copy the public key from the certificate */
    if (OE_ECCopyKey(&publicKeyImpl->pk, &impl->cert->pk, false) != 0)
        OE_RAISE(OE_FAILURE);

    /* Set the magic number */
    publicKeyImpl->magic = OE_EC_PUBLIC_KEY_MAGIC;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_CertChainGetLength(const OE_CertChain* chain, size_t* length)
{
    OE_Result result = OE_UNEXPECTED;
    const CertChain* impl = (const CertChain*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_CertChainValid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Set the length output parameter */
    *length = impl->referent->length;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_CertChainGetCert(
    const OE_CertChain* chain,
    size_t index,
    OE_Cert* cert)
{
    OE_Result result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;
    Cert* certImpl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        OE_Memset(cert, 0, sizeof(OE_Cert));

    /* Reject invalid parameters */
    if (!_CertChainValid(impl) || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Adjust the index to get the last certificate */
    if (index == OE_MAX_SIZE_T)
        index = impl->referent->length - 1;

    /* Find the certificate with this index */
    if (!(crt = _ReferentGetCert(impl->referent, index)))
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Initialize the implementation */
    _CertInit(certImpl, crt, impl->referent);

    result = OE_OK;

done:

    return result;
}

#if 0
static void _DumpASCII(const void* data_, size_t size)
{
    const uint8_t* data = (const uint8_t*)data_;

    for (size_t i = 0; i < size; i++)
    {
        uint8_t c = data[i];

        if (c >= ' ' && c <= '~')
        {
            printf("%c", c);
        }
        else
        {
            printf("%c", c);
            // printf("<%02X>", c);
        }
    }

    printf("\n");
}
#endif

#if 0
static void _DumpOID(const uint8_t* data, size_t size)
{
    printf("OID: ");

    for (size_t i = 0; i < size; i++)
    {
        printf("%u", data[i]);

        if (i + 1 != size)
            printf(".");
    }

    printf("\n");
}
#endif

#define MAX_OID_STRING_SIZE 128

/* Returns true when done */
typedef bool (*ParseExtensionsCallback)(
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args);

typedef struct _ParseExtensionsCallbackArgs
{
    OE_Result result;
    const char* oid;
    uint8_t* data;
    size_t* size;
} ParseExtensionsCallbackArgs;

static bool _ParseExtensionsCallback(
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args_)
{
    ParseExtensionsCallbackArgs* args = (ParseExtensionsCallbackArgs*)args_;

#if 0
    printf("== _ExtensionCallback()\n");
    printf("oid=%s\n", oid);
    printf("critical=%u\n", critical);
    printf("data=");
    OE_HexDump(data, size);
    printf("\n");
#endif

    if (OE_Strcmp(oid, args->oid) == 0)
    {
        /* If buffer is too small */
        if (size > *args->size)
        {
            *args->size = size;
            args->result = OE_BUFFER_TOO_SMALL;
            return true;
        }

        /* Copy to caller's buffer */
        if (args->data)
            OE_Memcpy(args->data, data, *args->size);

        *args->size = size;
        args->result = OE_OK;
        return true;
    }

    /* Keep parsing */
    return false;
}

static int _ParseExtensions(
    const uint8_t* data,
    size_t size,
    ParseExtensionsCallback callback,
    void* args)
{
    int ret = -1;
    uint8_t* p = (uint8_t*)data;
    uint8_t* end = p + size;
    size_t len;
    int r;

    if (!data)
        goto done;

    /* Parse tag that introduces the extensions */
    {
        int tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

        /* Get the tag and length of the entire packet */
        if (mbedtls_asn1_get_tag(&p, end, &len, tag) != 0)
            goto done;
    }

    /* Parse each extension of the form: [OID | CRITICAL | OCTETS] */
    while (end - p > 1)
    {
        char oidstr[MAX_OID_STRING_SIZE];
        int isCritical = 0;
        const uint8_t* octets;
        size_t octetsSize;

        /* Parse the OID */
        {
            mbedtls_x509_buf oid;

            /* Prase the OID tag */
            {
                int tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

                if (mbedtls_asn1_get_tag(&p, end, &len, tag) != 0)
                    goto done;

                oid.tag = p[0];
            }

            /* Parse the OID length */
            {
                if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) != 0)
                    goto done;

                oid.len = len;
                oid.p = p;
                p += oid.len;
            }

            /* Convert OID to a string */
            r = mbedtls_oid_get_numeric_string(oidstr, sizeof(oidstr), &oid);
            if (r < 0)
                goto done;
        }

        /* Parse the critical flag */
        {
            r = (mbedtls_asn1_get_bool(&p, end, &isCritical));
            if (r != 0 && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
                goto done;
        }

        /* Parse the octet string */
        {
            const int tag = MBEDTLS_ASN1_OCTET_STRING;
            if (mbedtls_asn1_get_tag(&p, end, &len, tag) != 0)
                goto done;

            octets = p;
            octetsSize = len;
            p += len;
        }

        /* Invoke the caller's callback (returns true when done) */
        if (callback(oidstr, isCritical, octets, octetsSize, args) == true)
        {
            ret = 0;
            goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

OE_Result OE_CertGetExtension(
    const OE_Cert* cert,
    const char* oid,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;
    const mbedtls_x509_buf* extensions; /* same as mbedtls_asn1_buf */

    /* Reject invalid parameters */
    if (!_CertValid(impl) || !oid || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get pointer to extensions */
    extensions = &impl->cert->v3_ext;

    /* Iterate over the extensions using a callback function */
    {
        ParseExtensionsCallbackArgs args;
        args.result = OE_NOT_FOUND;
        args.oid = oid;
        args.data = data;
        args.size = size;

        if (_ParseExtensions(
                extensions->p,
                extensions->len,
                _ParseExtensionsCallback,
                &args) != 0)
        {
            OE_RAISE(OE_FAILURE);
        }

        result = args.result;
        goto done;
    }

done:
    return result;
}
