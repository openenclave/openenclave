// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crl.h"
#include <openenclave/internal/crl.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openssl/x509.h>
#include <string.h>

/* Randomly generated magic number */
#define OE_CRL_MAGIC 0xe8c993b1cca24906

OE_STATIC_ASSERT(sizeof(crl_t) <= sizeof(oe_crl_t));

OE_INLINE void _crl_init(crl_t* impl, X509_CRL* crl)
{
    impl->magic = OE_CRL_MAGIC;
    impl->crl = crl;
}

bool crl_is_valid(const crl_t* impl)
{
    return impl && (impl->magic == OE_CRL_MAGIC) && impl->crl;
}

OE_INLINE void _crl_free(crl_t* impl)
{
    X509_CRL_free(impl->crl);
    memset(impl, 0, sizeof(crl_t));
}

oe_result_t oe_crl_read_der(
    oe_crl_t* crl,
    const uint8_t* der_data,
    size_t der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;
    BIO* bio = NULL;
    X509_CRL* x509_crl = NULL;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(crl_t));

    /* Check for invalid parameters */
    if (!der_data || !der_size || !crl)
        OE_RAISE(OE_UNEXPECTED);

    /* Create a BIO for reading the DER-formatted data */
    if (!(bio = BIO_new_mem_buf(der_data, der_size)))
        goto done;

    /* Read BIO into X509_CRL object */
    if (!(x509_crl = d2i_X509_CRL_bio(bio, NULL)))
        goto done;

    /* Initialize the implementation */
    _crl_init(impl, x509_crl);
    x509_crl = NULL;

    result = OE_OK;

done:

    if (x509_crl)
        X509_CRL_free(x509_crl);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_crl_free(oe_crl_t* crl)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;

    /* Check the parameter */
    if (!crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the CRL */
    _crl_free(impl);

    result = OE_OK;

done:
    return result;
}
