// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "crl.h"
#include <mbedtls/platform.h>
#include <openenclave/internal/crypto/crl.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include <string.h>

/* Randomly generated magic number */
#define OE_CRL_MAGIC 0xf8cf8e04f4ed40f3

OE_STATIC_ASSERT(sizeof(crl_t) <= sizeof(oe_crl_t));

OE_INLINE void _crl_init(crl_t* impl, mbedtls_x509_crl* crl)
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
    mbedtls_x509_crl_free(impl->crl);
    memset(impl->crl, 0, sizeof(mbedtls_x509_crl));
    mbedtls_free(impl->crl);
    memset(impl, 0, sizeof(crl_t));
}

oe_result_t oe_crl_read_der(
    oe_crl_t* crl,
    const uint8_t* der_data,
    size_t der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;
    mbedtls_x509_crl* x509_crl = NULL;
    int rc = 0;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(crl_t));

    /* Check for invalid parameters */
    if (!der_data || !der_size || !crl)
        OE_RAISE(OE_UNEXPECTED);

    /* Allocate memory for the CRL */
    if (!(x509_crl = mbedtls_calloc(1, sizeof(mbedtls_x509_crl))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the CRL structure */
    mbedtls_x509_crl_init(x509_crl);

    /* Parse the DER data to populate the mbedtls_x509_crl struct */
    rc = mbedtls_x509_crl_parse_der(x509_crl, der_data, der_size);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Initialize the implementation */
    _crl_init(impl, x509_crl);
    x509_crl = NULL;

    result = OE_OK;

done:

    if (x509_crl)
    {
        mbedtls_x509_crl_free(x509_crl);
        memset(x509_crl, 0, sizeof(mbedtls_x509_crl));
        mbedtls_free(x509_crl);
    }

    return result;
}

oe_result_t oe_crl_read_pem(
    oe_crl_t* crl,
    const uint8_t* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;
    mbedtls_x509_crl* x509_crl = NULL;
    int rc = 0;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(crl_t));

    /* Check for invalid parameters */
    if (!pem_data || !pem_size || !crl)
        OE_RAISE(OE_UNEXPECTED);

    /* Allocate memory for the CRL */
    if (!(x509_crl = mbedtls_calloc(1, sizeof(mbedtls_x509_crl))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the CRL structure */
    mbedtls_x509_crl_init(x509_crl);

    /* Parse the DER data to populate the mbedtls_x509_crl struct */
    rc = mbedtls_x509_crl_parse(x509_crl, pem_data, pem_size);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Initialize the implementation */
    _crl_init(impl, x509_crl);
    x509_crl = NULL;

    result = OE_OK;

done:

    if (x509_crl)
    {
        mbedtls_x509_crl_free(x509_crl);
        memset(x509_crl, 0, sizeof(mbedtls_x509_crl));
        mbedtls_free(x509_crl);
    }

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

oe_result_t oe_crl_get_update_dates(
    const oe_crl_t* crl,
    oe_datetime_t* last,
    oe_datetime_t* next)
{
    oe_result_t result = OE_UNEXPECTED;
    const crl_t* impl = (const crl_t*)crl;

    if (last)
        memset(last, 0, sizeof(oe_datetime_t));

    if (next)
        memset(next, 0, sizeof(oe_datetime_t));

    if (!crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (last)
    {
        last->year = (uint32_t)impl->crl->this_update.year;
        last->month = (uint32_t)impl->crl->this_update.mon;
        last->day = (uint32_t)impl->crl->this_update.day;
        last->hours = (uint32_t)impl->crl->this_update.hour;
        last->minutes = (uint32_t)impl->crl->this_update.min;
        last->seconds = (uint32_t)impl->crl->this_update.sec;
    }

    if (next)
    {
        next->year = (uint32_t)impl->crl->next_update.year;
        next->month = (uint32_t)impl->crl->next_update.mon;
        next->day = (uint32_t)impl->crl->next_update.day;
        next->hours = (uint32_t)impl->crl->next_update.hour;
        next->minutes = (uint32_t)impl->crl->next_update.min;
        next->seconds = (uint32_t)impl->crl->next_update.sec;
    }

    result = OE_OK;

done:

    return result;
}
