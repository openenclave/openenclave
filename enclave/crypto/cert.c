// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509_crt.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <string.h>
#include "crl.h"
#include "ctr_drbg.h"
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

typedef struct _referent
{
    /* The first certificate in the chain (crt->next points to the next) */
    mbedtls_x509_crt* crt;

    /* The length of the certificate chain */
    size_t length;

    /* Reference count */
    volatile uint64_t refs;
} Referent;

/* Allocate and initialize a new referent */
OE_INLINE Referent* _referent_new(void)
{
    Referent* referent;

    if (!(referent = (Referent*)mbedtls_calloc(1, sizeof(Referent))))
        return NULL;

    if (!(referent->crt =
              (mbedtls_x509_crt*)mbedtls_calloc(1, sizeof(mbedtls_x509_crt))))
    {
        mbedtls_free(referent);
        return NULL;
    }

    mbedtls_x509_crt_init(referent->crt);
    referent->length = 0;
    referent->refs = 1;

    return referent;
}

OE_INLINE mbedtls_x509_crt* _referent_get_cert(Referent* referent, size_t index)
{
    size_t i = 0;

    for (mbedtls_x509_crt* p = referent->crt; p; p = p->next, i++)
    {
        if (i == index)
            return p;
    }

    /* Out of bounds */
    return NULL;
}

/* Increase the reference count */
OE_INLINE void _referent_add_ref(Referent* referent)
{
    if (referent)
        oe_atomic_increment(&referent->refs);
}

/* Decrease the reference count and release if count becomes zero */
OE_INLINE void _referent_free(Referent* referent)
{
    if (!referent)
        return;

    /* If this was the last reference, release the object */
    if (oe_atomic_decrement(&referent->refs) == 0)
    {
        /* Release the MBEDTLS certificate */
        mbedtls_x509_crt_free(referent->crt);
        mbedtls_free(referent->crt);

        /* Free the referent structure */
        memset(referent, 0, sizeof(Referent));
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

typedef struct _cert
{
    uint64_t magic;

    /* If referent is non-null, points to a certificate within a chain */
    mbedtls_x509_crt* cert;

    /* Pointer to referent if this certificate is part of a chain */
    Referent* referent;
} Cert;

OE_STATIC_ASSERT(sizeof(Cert) <= sizeof(oe_cert_t));

OE_INLINE void _cert_init(
    Cert* impl,
    mbedtls_x509_crt* cert,
    Referent* referent)
{
    impl->magic = OE_CERT_MAGIC;
    impl->cert = cert;
    impl->referent = referent;
    _referent_add_ref(impl->referent);
}

OE_INLINE bool _cert_is_valid(const Cert* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->cert;
}

OE_INLINE void _cert_free(Cert* impl)
{
    /* Release the referent if its reference count is one */
    if (impl->referent)
    {
        /* impl->cert == &impl->referent->crt */
        _referent_free(impl->referent);
    }
    else
    {
        /* Release the MBEDTLS certificate */
        mbedtls_x509_crt_free(impl->cert);
        memset(impl->cert, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(impl->cert);
    }

    /* Clear the fields */
    memset(impl, 0, sizeof(Cert));
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

typedef struct _cert_chain
{
    uint64_t magic;

    /* Pointer to reference-counted implementation shared with Cert */
    Referent* referent;
} CertChain;

OE_STATIC_ASSERT(sizeof(CertChain) <= sizeof(oe_cert_chain_t));

OE_INLINE oe_result_t _cert_chain_init(CertChain* impl, Referent* referent)
{
    impl->magic = OE_CERT_CHAIN_MAGIC;
    impl->referent = referent;
    _referent_add_ref(referent);
    return OE_OK;
}

OE_INLINE bool _cert_chain_is_valid(const CertChain* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->referent;
}

/*
**==============================================================================
**
** Local helper functions:
**
**==============================================================================
*/

static bool _x509_buf_equal(
    const mbedtls_x509_buf* x,
    const mbedtls_x509_buf* y)
{
    return (x->tag == y->tag) && (x->len == y->len) &&
           memcmp(x->p, y->p, x->len) == 0;
}

// Find the last certificate in the chain and then verify that it's a
// self-signed certificate (a root certificate).
static mbedtls_x509_crt* _find_root_cert(mbedtls_x509_crt* chain)
{
    mbedtls_x509_crt* p = NULL;

    /* Find the last certificate in the list */
    for (p = chain; p->next; p = p->next)
        ;

    /* If the last certificate is not self-signed, then fail */
    if (!_x509_buf_equal(&p->subject_raw, &p->issuer_raw))
        return NULL;

    if (p == NULL)
        OE_TRACE_ERROR("root cert was not found\n");

    return p;
}

/* Return true if the CRL list contains a CRL for this CA. */
static mbedtls_x509_crl* _crl_list_find_issuer_for_cert(
    mbedtls_x509_crl* crl_list,
    mbedtls_x509_crt* crt)
{
    for (mbedtls_x509_crl* p = crl_list; p; p = p->next)
    {
        if (_x509_buf_equal(&p->issuer_raw, &crt->subject_raw))
            return p;
    }
    OE_TRACE_ERROR("CRL list does not contains a CRL for this CA\n");
    return NULL;
}

/**
 * Return true is time t1 is chronologically before or at time t2.
 */
static bool _mbedtls_x509_time_is_before_or_equal(
    const mbedtls_x509_time* t1,
    const mbedtls_x509_time* t2)
{
    if (t1->year != t2->year)
        return t1->year < t2->year;
    if (t1->mon != t2->mon)
        return t1->mon < t2->mon;
    if (t1->day != t2->day)
        return t1->day < t2->day;
    if (t1->hour != t2->hour)
        return t1->hour < t2->hour;
    if (t1->min != t2->min)
        return t1->min < t2->min;
    return t1->sec <= t2->sec;
}

/**
 * Reorder the cert chain to be leaf->intermeditate->root.
 * This order simplifies cert validation.
 * The preferred order is also the reverse chronological order of issue dates.
 * Before or equal comparison is used to preserve stable sorting, to be
 * consistent with the sort function in the host side.
 *
 * Note: This sorting does not handle certs that are issues within a second of
 * each other since mbedtls_x509_time's  resolution is seconds. Such certs can
 * arise in testing code that generates a cert chain on the fly. See issue #864.
 */
static mbedtls_x509_crt* _sort_certs_by_issue_date(mbedtls_x509_crt* chain)
{
    mbedtls_x509_crt* sorted = NULL;
    mbedtls_x509_crt* oldest = NULL;
    mbedtls_x509_crt** p_oldest = NULL;
    mbedtls_x509_crt** p = NULL;

    while (chain)
    {
        // Set the start of the chain as the oldest cert.
        p_oldest = &chain;

        // Iterate through the chain to select the cert having
        // the oldest issue date.
        p = &chain->next;
        while (*p)
        {
            // Update oldest if a new oldest cert is found.
            if (_mbedtls_x509_time_is_before_or_equal(
                    &(*p)->valid_from, &(*p_oldest)->valid_from))
            {
                p_oldest = p;
            }
            p = &(*p)->next;
        }

        // Remove next oldest cert from chain.
        oldest = *p_oldest;
        *p_oldest = oldest->next;

        // Recursively insert the next oldest cert at the front of the sorted
        // list (newest cert at the beginning).
        oldest->next = sorted;
        sorted = oldest;
    }
    return sorted;
}

/* Call mbedlts_x509_crt_verify and handle error logging */
static oe_result_t _mbedtls_x509_crt_verify(
    mbedtls_x509_crt* leaf_cert,
    mbedtls_x509_crt* ca_cert_chain,
    mbedtls_x509_crl* ca_crls)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t flags = 0;
    if (mbedtls_x509_crt_verify(
            leaf_cert, ca_cert_chain, ca_crls, NULL, &flags, NULL, NULL) != 0)
    {
        char error[1024] = {0};
        mbedtls_x509_crt_verify_info(error, sizeof(error), "", flags);
        if (flags & MBEDTLS_X509_BADCERT_REVOKED)
            result = OE_VERIFY_REVOKED;
        else if (flags & MBEDTLS_X509_BADCRL_EXPIRED)
            result = OE_VERIFY_CRL_EXPIRED;
        else
            result = OE_VERIFY_FAILED;

        OE_RAISE_MSG(
            result,
            "mbedtls_x509_crt_verify failed with %s (flags=0x%x)\n",
            error,
            flags);
    }

    result = OE_OK;

done:
    return result;
}

/* Verify each certificate in the chain against its predecessors. */
static oe_result_t _verify_whole_chain(mbedtls_x509_crt* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_x509_crt* root;

    if (!chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the root certificate in this chain */
    if (!(root = _find_root_cert(chain)))
        OE_RAISE(OE_VERIFY_FAILED);

    // Verify each certificate in the chain against the following subchain.
    // For each i, verify chain[i] against chain[i+1:...].
    for (mbedtls_x509_crt* p = chain; p && p->next; p = p->next)
    {
        /* Pointer to subchain of certificates (predecessors) */
        mbedtls_x509_crt* subchain = p->next;

        /* Verify the next certificate against its following predecessors */
        OE_CHECK(_mbedtls_x509_crt_verify(p, subchain, NULL));

        /* If the final certificate is not the root */
        if (subchain->next == NULL && root != subchain)
            OE_RAISE_MSG(
                OE_VERIFY_FAILED, "Last certificate in the chain is not Root");
    }

    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** _parse_extensions()
**
**==============================================================================
*/

/* Returns true when done */
typedef bool (*parse_extensions_callback_t)(
    size_t index,
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args);

typedef struct _find_extension_args
{
    oe_result_t result;
    const char* oid;
    uint8_t* data;
    size_t* size;
} FindExtensionArgs;

static bool _find_extension(
    size_t index,
    const char* oid,
    bool critical,
    const uint8_t* data,
    size_t size,
    void* args_)
{
    FindExtensionArgs* args = (FindExtensionArgs*)args_;
    OE_UNUSED(index);
    OE_UNUSED(critical);

    if (strcmp(oid, args->oid) == 0)
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
            args->result = oe_memcpy_s(args->data, *args->size, data, size);
        else
            args->result = OE_OK;

        *args->size = size;
        return true;
    }

    /* Keep parsing */
    return false;
}

typedef struct _get_extension_count_args
{
    size_t* count;
} GetExtensionCountArgs;

typedef struct _get_extension_args
{
    oe_result_t result;
    size_t index;
    oe_oid_string_t* oid;
    uint8_t* data;
    size_t* size;
} GetExtensionArgs;

/* Parse the extensions on an MBEDTLS X509 certificate */
static int _parse_extensions(
    const mbedtls_x509_crt* crt,
    parse_extensions_callback_t callback,
    void* args)
{
    int ret = -1;
    uint8_t* p = crt->v3_ext.p;
    uint8_t* end = p + crt->v3_ext.len;
    size_t len;
    int rc;
    size_t index = 0;

    if (!p)
    {
        ret = 0;
        goto done;
    }
    /* Parse tag that introduces the extensions */
    {
        int tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

        /* Get the tag and length of the entire packet */
        rc = mbedtls_asn1_get_tag(&p, end, &len, tag);
        if (rc != 0)
        {
            OE_TRACE_ERROR("mbedtls_asn1_get_tag rc = 0x%x\n", rc);
            goto done;
        }
    }

    /* Parse each extension of the form: [OID | CRITICAL | OCTETS] */
    while (end - p > 1)
    {
        oe_oid_string_t oidstr;
        int is_critical = 0;
        const uint8_t* octets;
        size_t octets_size;

        /* Parse the OID */
        {
            mbedtls_x509_buf oid;

            /* Parse the OID tag */
            {
                int tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

                rc = mbedtls_asn1_get_tag(&p, end, &len, tag);
                if (rc != 0)
                {
                    OE_TRACE_ERROR("mbedtls_asn1_get_tag rc = 0x%x\n", rc);
                    goto done;
                }

                oid.tag = p[0];
            }

            /* Parse the OID length */
            {
                rc = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID);
                if (rc != 0)
                {
                    OE_TRACE_ERROR("mbedtls_asn1_get_tag rc = 0x%x\n", rc);
                    goto done;
                }

                oid.len = len;
                oid.p = p;
                p += oid.len;
            }

            /* Convert OID to a string */
            rc = mbedtls_oid_get_numeric_string(
                oidstr.buf, sizeof(oidstr.buf), &oid);
            if (rc < 0)
            {
                OE_TRACE_ERROR(
                    "mbedtls_oid_get_numeric_string rc = 0x%x\n", rc);
                goto done;
            }
        }

        /* Parse the critical flag */
        {
            rc = (mbedtls_asn1_get_bool(&p, end, &is_critical));
            if (rc != 0 && rc != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            {
                OE_TRACE_ERROR("mbedtls_asn1_get_bool rc = 0x%x\n", rc);
                goto done;
            }
        }

        /* Parse the octet string */
        {
            const int tag = MBEDTLS_ASN1_OCTET_STRING;
            rc = mbedtls_asn1_get_tag(&p, end, &len, tag);
            if (rc != 0)
            {
                OE_TRACE_ERROR("mbedtls_asn1_get_tag rc = 0x%x\n", rc);
                goto done;
            }

            octets = p;
            octets_size = len;
            p += len;
        }

        /* Invoke the caller's callback (returns true when done) */
        if (callback(index, oidstr.buf, is_critical, octets, octets_size, args))
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
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;
    int rc = 0;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(Cert));

    /* Check parameters */
    if (!pem_data || !pem_size || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate memory for the certificate */
    if (!(crt = mbedtls_calloc(1, sizeof(mbedtls_x509_crt))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the certificate structure */
    mbedtls_x509_crt_init(crt);

    /* Read the PEM buffer into DER format */
    rc = mbedtls_x509_crt_parse(crt, (const uint8_t*)pem_data, pem_size);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls_x509_crt_parse rc = 0x%x\n", rc);

    /* Initialize the implementation */
    _cert_init(impl, crt, NULL);
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        memset(crt, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(crt);
    }

    return result;
}

oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;
    int rc = 0;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(Cert));

    /* Check parameters */
    if (!der_data || !der_size || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate memory for the certificate */
    if (!(crt = mbedtls_calloc(1, sizeof(mbedtls_x509_crt))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the certificate structure */
    mbedtls_x509_crt_init(crt);

    /* Parse a single DER formatted certificate and add it to the chained list
     */
    rc = mbedtls_x509_crt_parse_der(crt, (const uint8_t*)der_data, der_size);
    if (rc != 0)
        OE_RAISE(OE_CRYPTO_ERROR, "mbedtls_x509_crt_parse rc= 0x%x\n", rc);

    /* Initialize the implementation */
    _cert_init(impl, crt, NULL);
    crt = NULL;

    result = OE_OK;

done:

    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        memset(crt, 0, sizeof(mbedtls_x509_crt));
        mbedtls_free(crt);
    }

    return result;
}

oe_result_t oe_cert_free(oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* impl = (Cert*)cert;

    /* Check the parameter */
    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    _cert_free(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_read_pem(
    oe_cert_chain_t* chain,
    const void* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;
    Referent* referent = NULL;
    int rc = 0;
    uint8_t* tmp_pem_data = (uint8_t*)pem_data;
    size_t tmp_pem_size = pem_size;

    /* Clear the implementation (making it invalid) */
    if (impl)
        memset(impl, 0, sizeof(CertChain));

    /* Check parameters */
    if (!pem_data || !pem_size || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    // mbedtls_x509_crt_parse() requires a trailing zero in its input buffer.
    // If the input pem_data buffer does not have a trailing zero,
    // we allocate a tmp buffer to add it.
    if (strnlen((const char*)pem_data, pem_size) == pem_size)
    {
        tmp_pem_size = pem_size + 1;
        if (!(tmp_pem_data = (uint8_t*)oe_malloc(tmp_pem_size)))
            OE_RAISE(OE_OUT_OF_MEMORY);

        oe_memcpy_s(tmp_pem_data, tmp_pem_size, pem_data, pem_size);
        tmp_pem_data[pem_size] = '\0';
    }

    /* Create the referent */
    if (!(referent = _referent_new()))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Read the PEM buffer into DER format */
    rc = mbedtls_x509_crt_parse(
        referent->crt, (const uint8_t*)tmp_pem_data, tmp_pem_size);

    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "mbedtls_x509_crt_parse rc = 0x%x\n", rc);

    /* Reorder certs in the chain to preferred order */
    referent->crt = _sort_certs_by_issue_date(referent->crt);

    /* Verify the whole certificate chain */
    OE_CHECK(_verify_whole_chain(referent->crt));

    /* Calculate the length of the certificate chain */
    for (mbedtls_x509_crt* p = referent->crt; p; p = p->next)
        referent->length++;

    /* Initialize the implementation and increment reference count */
    OE_CHECK(_cert_chain_init(impl, referent));

    result = OE_OK;

done:

    if (tmp_pem_data && (tmp_pem_data != pem_data))
        oe_free(tmp_pem_data);

    _referent_free(referent);
    return result;
}

oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    CertChain* impl = (CertChain*)chain;

    /* Check the parameter */
    if (!_cert_chain_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Release the referent if the reference count is one */
    _referent_free(impl->referent);

    /* Clear the implementation (making it invalid) */
    memset(impl, 0, sizeof(CertChain));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls)
{
    oe_result_t result = OE_UNEXPECTED;
    Cert* cert_impl = (Cert*)cert;
    CertChain* chain_impl = (CertChain*)chain;
    mbedtls_x509_crl* crl_list = NULL;

    /* Reject invalid certificate */
    if (!_cert_is_valid(cert_impl))
    {
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid cert parameter", NULL);
    }

    /* Reject invalid certificate chain */
    if (chain && !_cert_chain_is_valid(chain_impl))
    {
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid chain parameter", NULL);
    }

    // Build the list of CRLS if any. Copy them onto auxiliary memory
    // to avoid modifying them when putting them on the list.
    if (crls && num_crls)
    {
        mbedtls_x509_crl* last = NULL;

        for (size_t i = 0; i < num_crls; i++)
        {
            const crl_t* crl_impl = (crl_t*)crls[i];
            mbedtls_x509_crl* p;

            if (!crl_is_valid(crl_impl))
                OE_RAISE_MSG(
                    OE_INVALID_PARAMETER, "Invalid crls parameter", NULL);

            if (!(p = malloc(sizeof(mbedtls_x509_crl))))
                OE_RAISE(OE_OUT_OF_MEMORY);

            OE_CHECK(oe_memcpy_s(
                p, sizeof(*p), crl_impl->crl, sizeof(mbedtls_x509_crl)));

            /* Append to the linked-list */
            {
                p->next = NULL;

                if (crl_list)
                    last->next = p;
                else
                    crl_list = p;
            }

            last = p;
        }
    }

    /* Verify the certificate */
    OE_CHECK(_mbedtls_x509_crt_verify(
        cert_impl->cert,
        (chain != NULL) ? chain_impl->referent->crt : cert_impl->cert,
        crl_list));

    if (chain)
    {
        /* Verify every certificate in the certificate chain. */
        for (mbedtls_x509_crt* p = chain_impl->referent->crt; p; p = p->next)
        {
            /* Verify the current certificate in the chain. */
            OE_CHECK(_mbedtls_x509_crt_verify(
                p,
                ((chain != NULL) ? chain_impl->referent->crt : NULL),
                crl_list));

            /* Verify that the CRL list has an issuer for this certificate. */
            if (crl_list)
            {
                if (!_crl_list_find_issuer_for_cert(crl_list, p))
                {
                    OE_RAISE_MSG(
                        OE_VERIFY_CRL_MISSING,
                        "Unable to get certificate CRL",
                        NULL);
                }
            }
        }
    }
    result = OE_OK;

done:

    if (crl_list)
    {
        /* Free the linked list of CRL objects */
        for (mbedtls_x509_crl* p = crl_list; p;)
        {
            mbedtls_x509_crl* next = p->next;
            free(p);
            p = next;
        }
    }

    return result;
}

oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_rsa_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If certificate does not contain an RSA key */
    if (!oe_is_rsa_key(&impl->cert->pk))
        OE_RAISE(OE_FAILURE);

    /* Copy the public key from the certificate */
    OE_CHECK(oe_rsa_public_key_init(public_key, &impl->cert->pk));

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If certificate does not contain an EC key */
    if (!oe_is_ec_key(&impl->cert->pk))
        OE_RAISE_NO_TRACE(OE_CRYPTO_ERROR);

    /* Copy the public key from the certificate */
    OE_RAISE(oe_ec_public_key_init(public_key, &impl->cert->pk));

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
    if (!_cert_chain_is_valid(impl) || !length)
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
    Cert* cert_impl = (Cert*)cert;
    mbedtls_x509_crt* crt = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        memset(cert, 0, sizeof(oe_cert_t));

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !cert)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the certificate with this index */
    if (!(crt = _referent_get_cert(impl->referent, index)))
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Initialize the implementation */
    _cert_init(cert_impl, crt, impl->referent);

    result = OE_OK;

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
    if (!_cert_is_valid(impl) || !oid || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the extension with the given OID using a callback */
    {
        FindExtensionArgs args;
        args.result = OE_NOT_FOUND;
        args.oid = oid;
        args.data = data;
        args.size = size;

        if (_parse_extensions(impl->cert, _find_extension, &args) != 0)
            OE_RAISE(OE_FAILURE);

        result = args.result;
        goto done;
    }

done:
    return result;
}

oe_result_t oe_gen_custom_x509_cert(
    oe_cert_config_t* config,
    unsigned char* cert_buf,
    size_t cert_buf_size,
    size_t* bytes_written)
{
    oe_result_t result = OE_CRYPTO_ERROR;
    mbedtls_mpi serial;
    mbedtls_x509write_cert x509cert = {0};
    mbedtls_pk_context subject_key;
    mbedtls_pk_context issuer_key;
    mbedtls_ctr_drbg_context* ctr_drbg = NULL;
    mbedtls_entropy_context entropy;
    unsigned char* buff = NULL;
    int ret = 0;

    mbedtls_pk_init(&subject_key);
    mbedtls_pk_init(&issuer_key);
    mbedtls_mpi_init(&serial);
    // mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&x509cert);
    mbedtls_x509write_crt_set_md_alg(&x509cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&x509cert, &subject_key);
    mbedtls_x509write_crt_set_issuer_key(&x509cert, &issuer_key);

    if ((buff = malloc(cert_buf_size)) == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Get the drbg object */
    if (!(ctr_drbg = oe_mbedtls_get_drbg()))
        OE_RAISE(OE_CRYPTO_ERROR);

    // create pk_context for both public and private keys
    ret = mbedtls_pk_parse_public_key(
        &subject_key,
        (const unsigned char*)config->public_key_buf,
        config->public_key_buf_size);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    OE_TRACE_VERBOSE(
        "custom_x509_cert: key type:%d", mbedtls_pk_get_type(&subject_key));

    ret = mbedtls_pk_parse_key(
        &issuer_key,
        (const unsigned char*)config->private_key_buf,
        config->private_key_buf_size,
        NULL,
        0);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    ret = mbedtls_x509write_crt_set_subject_name(
        &x509cert, (const char*)config->subject_name);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    ret = mbedtls_x509write_crt_set_issuer_name(
        &x509cert, (const char*)config->issuer_name);

    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    ret = mbedtls_mpi_read_string(&serial, 10, "1");
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    ret = mbedtls_x509write_crt_set_serial(&x509cert, &serial);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    ret = mbedtls_x509write_crt_set_validity(
        &x509cert,
        (const char*)config->date_not_valid_before,
        (const char*)config->date_not_valid_after);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    // Set the basicConstraints extension for a CRT
    ret = mbedtls_x509write_crt_set_basic_constraints(
        &x509cert,
        0, // is_ca
        -1);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    // Set the subjectKeyIdentifier extension for a CRT Requires that
    // mbedtls_x509write_crt_set_subject_key() has been called before
    ret = mbedtls_x509write_crt_set_subject_key_identifier(&x509cert);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    // Set the authorityKeyIdentifier extension for a CRT Requires that
    // mbedtls_x509write_crt_set_issuer_key() has been called before.
    ret = mbedtls_x509write_crt_set_authority_key_identifier(&x509cert);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    ret = mbedtls_x509write_crt_set_extension(
        &x509cert,
        (char*)config->ext_oid,
        config->ext_oid_size,
        0,
        (const uint8_t*)config->ext_data_buf,
        config->ext_data_buf_size);
    if (ret)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "ret = 0x%x ", ret);

    // Write a built up certificate to a X509 DER structure Note: data
    // is written at the end of the buffer! Use the return value to
    // determine where you should start using the buffer.
    *bytes_written = (size_t)mbedtls_x509write_crt_der(
        &x509cert, buff, cert_buf_size, mbedtls_ctr_drbg_random, ctr_drbg);
    if (*bytes_written <= 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "bytes_written = 0x%x ", *bytes_written);

    OE_CHECK(oe_memcpy_s(
        (void*)cert_buf,
        cert_buf_size,
        (const void*)(buff + cert_buf_size - *bytes_written),
        *bytes_written));
    OE_TRACE_VERBOSE("bytes_written = 0x%x", *bytes_written);

    result = OE_OK;
done:
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&x509cert);
    // mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&issuer_key);
    mbedtls_pk_free(&subject_key);
    free(buff);
    if (ret)
        result = OE_CRYPTO_ERROR;

    return result;
}

oe_result_t oe_cert_get_validity_dates(
    const oe_cert_t* cert,
    oe_datetime_t* not_before,
    oe_datetime_t* not_after)
{
    oe_result_t result = OE_UNEXPECTED;
    const Cert* impl = (const Cert*)cert;

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (not_before)
    {
        memset(not_before, 0, sizeof(oe_datetime_t));

        not_before->year = (uint32_t)impl->cert->valid_from.year;
        not_before->month = (uint32_t)impl->cert->valid_from.mon;
        not_before->day = (uint32_t)impl->cert->valid_from.day;
        not_before->hours = (uint32_t)impl->cert->valid_from.hour;
        not_before->minutes = (uint32_t)impl->cert->valid_from.min;
        not_before->seconds = (uint32_t)impl->cert->valid_from.sec;
    }

    if (not_after)
    {
        memset(not_after, 0, sizeof(oe_datetime_t));

        not_after->year = (uint32_t)impl->cert->valid_to.year;
        not_after->month = (uint32_t)impl->cert->valid_to.mon;
        not_after->day = (uint32_t)impl->cert->valid_to.day;
        not_after->hours = (uint32_t)impl->cert->valid_to.hour;
        not_after->minutes = (uint32_t)impl->cert->valid_to.min;
        not_after->seconds = (uint32_t)impl->cert->valid_to.sec;
    }
    result = OE_OK;

done:
    return result;
}
