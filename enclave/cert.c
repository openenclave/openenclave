// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/asn1.h>
#include <mbedtls/config.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>
#include <openenclave/bits/thread.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/string.h>
#include <openenclave/internal/utils.h>
#include "crl.h"
#include "ec.h"
#include "pem.h"
#include "rsa.h"

/*
**==============================================================================
**
** Referent:
**     Define a structure and functions to represent a reference-counted
**     MBEDTLS certificate chain. This type is used by both oe_cert_t and
**     oe_cert_chain_t. This allows oe_cert_chain_get_cert() to avoid making a
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
        oe_atomic_increment(&referent->refs);
}

/* Decrease the reference count and release if count becomes zero */
OE_INLINE void _ReferentFree(Referent* referent)
{
    /* If this was the last reference, release the object */
    if (oe_atomic_decrement(&referent->refs) == 0)
    {
        /* Release the MBEDTLS certificate */
        mbedtls_x509_crt_free(&referent->crt);

        /* Free the referent structure */
        oe_memset(referent, 0, sizeof(Referent));
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

OE_STATIC_ASSERT(sizeof(Cert) <= sizeof(oe_cert_t));

OE_INLINE void _CertInit(Cert* impl, mbedtls_x509_crt* cert, Referent* referent)
{
    impl->magic = OE_CERT_MAGIC;
    impl->cert = cert;
    impl->referent = referent;
    _ReferentAddRef(impl->referent);
}

OE_INLINE bool _CertIsValid(const Cert* impl)
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
        oe_memset(impl->cert, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(impl->cert);
    }

    /* Clear the fields */
    oe_memset(impl, 0, sizeof(Cert));
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

OE_STATIC_ASSERT(sizeof(CertChain) <= sizeof(oe_cert_chain_t));

OE_INLINE oe_result_t _CertChainInit(CertChain* impl, Referent* referent)
{
    impl->magic = OE_CERT_CHAIN_MAGIC;
    impl->referent = referent;
    _ReferentAddRef(referent);
    return OE_OK;
}

OE_INLINE bool _CertChainIsValid(const CertChain* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->referent;
}

/*
**==============================================================================
**
** Location helper functions:
**
**==============================================================================
*/

static void _SetErr(oe_verify_cert_error_t* error, const char* str)
{
    if (error)
        oe_strlcpy(error->buf, str, sizeof(error->buf));
}

/* Find the first self-signed certificate in the chain. */
static mbedtls_x509_crt* _FindRootCert(mbedtls_x509_crt* chain)
{
    for (mbedtls_x509_crt* p = chain; p; p = p->next)
    {
        const mbedtls_x509_buf* subject = &p->subject_raw;
        const mbedtls_x509_buf* issuer = &p->issuer_raw;

        if (subject->tag == issuer->tag && subject->len == issuer->len &&
            oe_memcmp(subject->p, issuer->p, subject->len) == 0)
        {
            return p;
        }
    }

    /* Not found */
    return NULL;
}

/* Verify each certificate in the chain against its predecessors. */
static oe_result_t _VerifyWholeChain(mbedtls_x509_crt* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t flags = 0;
    mbedtls_x509_crt* root;

    if (!chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the root certificate in this chain */
    if (!(root = _FindRootCert(chain)))
        OE_RAISE(OE_FAILURE);

    // Verify each certificate in the chain against the following subchain.
    // For each i, verify chain[i] against chain[i+1:...].
    for (mbedtls_x509_crt* p = chain; p && p->next; p = p->next)
    {
        /* Pointer to subchain of certificates (predecessors) */
        mbedtls_x509_crt* subchain = p->next;

        /* Verify the next certificate against its following predecessors */
        int r = mbedtls_x509_crt_verify(
            p, subchain, NULL, NULL, &flags, NULL, NULL);

        /* Raise an error if any */
        if (r != 0)
            OE_RAISE(OE_FAILURE);

        /* If the final certificate is not the root */
        if (subchain->next == NULL && root != subchain)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** _ParseExtensions()
**
**==============================================================================
*/

/* Returns true when done */
typedef bool (*ParseExtensions)(
    size_t index,
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args);

typedef struct _FindExtensionArgs
{
    oe_result_t result;
    const char* oid;
    uint8_t* data;
    size_t* size;
} FindExtensionArgs;

static bool _FindExtension(
    size_t index,
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args_)
{
    FindExtensionArgs* args = (FindExtensionArgs*)args_;

    if (oe_strcmp(oid, args->oid) == 0)
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
            oe_memcpy(args->data, data, *args->size);

        *args->size = size;
        args->result = OE_OK;
        return true;
    }

    /* Keep parsing */
    return false;
}

typedef struct _GetExtensionCountArgs
{
    size_t* count;
} GetExtensionCountArgs;

static bool _GetExtensionCount(
    size_t index,
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args_)
{
    GetExtensionCountArgs* args = (GetExtensionCountArgs*)args_;

    (*args->count)++;

    return false;
}

typedef struct _GetExtensionArgs
{
    oe_result_t result;
    size_t index;
    oe_oid_string_t* oid;
    uint8_t* data;
    size_t* size;
} GetExtensionArgs;

static bool _GetExtension(
    size_t index,
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args_)
{
    GetExtensionArgs* args = (GetExtensionArgs*)args_;

    if (args->index == index)
    {
        /* If buffer is too small */
        if (size > *args->size)
        {
            *args->size = size;
            args->result = OE_BUFFER_TOO_SMALL;
            return true;
        }

        /* Copy the OID to caller's buffer */
        oe_strlcpy(args->oid->buf, oid, sizeof(oe_oid_string_t));

        /* Copy to caller's buffer */
        if (args->data)
            oe_memcpy(args->data, data, *args->size);

        *args->size = size;
        args->result = OE_OK;
        return true;
    }

    /* Keep parsing */
    return false;
}

/* Parse the extensions on an MBEDTLS X509 certificate */
static int _ParseExtensions(
    const mbedtls_x509_crt* crt,
    ParseExtensions callback,
    void* args)
{
    int ret = -1;
    uint8_t* p = crt->v3_ext.p;
    uint8_t* end = p + crt->v3_ext.len;
    size_t len;
    int r;
    size_t index = 0;

    if (!p)
        return 0;

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
        oe_oid_string_t oidstr;
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
            r = mbedtls_oid_get_numeric_string(
                oidstr.buf, sizeof(oidstr.buf), &oid);
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
        if (callback(index, oidstr.buf, isCritical, octets, octetsSize, args))
        {
            ret = 0;
            goto done;
        }

        /* Increment the index */
        index++;
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

oe_result_t oe_cert_read_pem(
    const void* pemData,
    size_t pemSize,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the implementation */
    if (impl)
        oe_memset(impl, 0, sizeof(Cert));

    /* Check parameters */
    if (!pemData || !pemSize || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (oe_strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate memory for the certificate */
    if (!(crt = mbedtls_calloc(1, sizeof(mbedtls_x509_crt))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the certificate structure */
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
        oe_memset(crt, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(crt);
    }

    return result;
}

oe_result_t oe_cert_free(oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;

    /* Check the parameter */
    if (!_CertIsValid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    _CertFree(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_read_pem(
    const void* pemData,
    size_t pemSize,
    oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;
    Referent* referent = NULL;

    /* Clear the implementation (making it invalid) */
    if (impl)
        oe_memset(impl, 0, sizeof(CertChain));

    /* Check parameters */
    if (!pemData || !pemSize || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (oe_strnlen((const char*)pemData, pemSize) != pemSize - 1)
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

    /* Verify the whole certificate chain */
    OE_CHECK(_VerifyWholeChain(&referent->crt));

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

oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;

    /* Check the parameter */
    if (!_CertChainIsValid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the referent if the reference count is one */
    _ReferentFree(impl->referent);

    /* Clear the implementation (making it invalid) */
    oe_memset(impl, 0, sizeof(CertChain));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* crl,
    oe_verify_cert_error_t* error)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* certImpl = (Cert*)cert;
    CertChain* chainImpl = (CertChain*)chain;
    crl_t* crl_impl = (crl_t*)crl;
    uint32_t flags = 0;

    /* Initialize error */
    if (error)
        *error->buf = '\0';

    /* Reject invalid certificate */
    if (!_CertIsValid(certImpl))
    {
        _SetErr(error, "invalid cert parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject invalid certificate chain */
    if (!_CertChainIsValid(chainImpl))
    {
        _SetErr(error, "invalid chain parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject invalid CRL */
    if (crl_impl && !crl_is_valid(crl_impl))
    {
        _SetErr(error, "invalid crl parameter");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Verify the certificate */
    if (mbedtls_x509_crt_verify(
            certImpl->cert,
            &chainImpl->referent->crt,
            crl_impl ? crl_impl->crl : NULL,
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

oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Clear public key for all error pathways */
    if (publicKey)
        oe_memset(publicKey, 0, sizeof(oe_rsa_public_key_t));

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If certificate does not contain an RSA key */
    if (!oe_is_rsa_key(&impl->cert->pk))
        OE_RAISE(OE_FAILURE);

    /* Copy the public key from the certificate */
    OE_CHECK(oe_rsa_public_key_init(publicKey, &impl->cert->pk));

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Clear public key for all error pathways */
    if (publicKey)
        oe_memset(publicKey, 0, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If certificate does not contain an EC key */
    if (!oe_is_ec_key(&impl->cert->pk))
        OE_RAISE(OE_FAILURE);

    /* Copy the public key from the certificate */
    OE_RAISE(oe_ec_public_key_init(publicKey, &impl->cert->pk));

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_get_length(
    const oe_cert_chain_t* chain,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    const CertChain* impl = (const CertChain*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_CertChainIsValid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Set the length output parameter */
    *length = impl->referent->length;

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_chain_get_cert(
    const oe_cert_chain_t* chain,
    size_t index,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;
    Cert* certImpl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        oe_memset(cert, 0, sizeof(oe_cert_t));

    /* Reject invalid parameters */
    if (!_CertChainIsValid(impl) || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the certificate with this index */
    if (!(crt = _ReferentGetCert(impl->referent, index)))
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Initialize the implementation */
    _CertInit(certImpl, crt, impl->referent);

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_extension_count(const oe_cert_t* cert, size_t* count)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    if (count)
        *count = 0;

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !count)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the extension count using a callback */
    {
        GetExtensionCountArgs args;
        args.count = count;

        if (_ParseExtensions(impl->cert, _GetExtensionCount, &args) != 0)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_get_root_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    OE_CHECK(oe_cert_chain_get_cert(chain, length - 1, cert));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_get_extension(
    const oe_cert_t* cert,
    size_t index,
    oe_oid_string_t* oid,
    uint8_t* data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !oid || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the extension with the given OID using a callback */
    {
        GetExtensionArgs args;
        args.result = OE_OUT_OF_BOUNDS;
        args.index = index;
        args.oid = oid;
        args.data = data;
        args.size = size;

        if (_ParseExtensions(impl->cert, _GetExtension, &args) != 0)
            OE_RAISE(OE_FAILURE);

        result = args.result;
        goto done;
    }

done:
    return result;
}

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !oid || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the extension with the given OID using a callback */
    {
        FindExtensionArgs args;
        args.result = OE_NOT_FOUND;
        args.oid = oid;
        args.data = data;
        args.size = size;

        if (_ParseExtensions(impl->cert, _FindExtension, &args) != 0)
            OE_RAISE(OE_FAILURE);

        result = args.result;
        goto done;
    }

done:
    return result;
}

oe_result_t oe_cert_chain_get_leaf_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    OE_CHECK(oe_cert_chain_get_cert(chain, 0, cert));
    result = OE_OK;

done:
    return result;
}

// Convert an X509 name to a string in this format: "/CN=Name1/O=Name2/L=Name3"
static oe_result_t _x509_name_to_string(
    mbedtls_x509_name* name,
    char* str,
    size_t* str_size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Iterate until the local buffer is big enough to hold the issuer name */
    for (size_t buf_size = 256; true; buf_size *= 2)
    {
        char buf[buf_size];
        int n = mbedtls_x509_dn_gets(buf, buf_size, name);

        if (n > 0)
        {
            // Convert subject to OpenSSL format with slash delimiters:
            // "CN=Name1, O=Name2, L=Name3" => "/CN=Name1/O=Name2/L=Name3"
            oe_string_substitute(buf, buf_size, ", ", "/");
            const size_t size = oe_string_insert(buf, buf_size, 0, "/");

            if (size > *str_size)
            {
                *str_size = size;
                OE_RAISE(OE_BUFFER_TOO_SMALL);
            }

            if (str)
                oe_memcpy(str, buf, *str_size);

            break;
        }
        else if (n != MBEDTLS_ERR_X509_BUFFER_TOO_SMALL)
        {
            OE_RAISE(OE_FAILURE);
        }
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_get_subject(
    const oe_cert_t* cert,
    char* subject,
    size_t* subject_size)
{
    const Cert* impl = (const Cert*)cert;
    oe_result_t result = OE_UNEXPECTED;

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !subject_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If the subject buffer is null, then the size must be zero */
    if (!subject && *subject_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Iterate until the local buffer is big enough to hold the subject name */
    OE_CHECK(_x509_name_to_string(&impl->cert->subject, subject, subject_size));

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_get_issuer(
    const oe_cert_t* cert,
    char* issuer,
    size_t* issuer_size)
{
    const Cert* impl = (const Cert*)cert;
    oe_result_t result = OE_UNEXPECTED;

    /* Reject invalid parameters */
    if (!_CertIsValid(impl) || !issuer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If the issuer buffer is null, then the size must be zero */
    if (!issuer && *issuer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert the X509 name to string format */
    OE_CHECK(_x509_name_to_string(&impl->cert->issuer, issuer, issuer_size));

    result = OE_OK;

done:

    return result;
}
