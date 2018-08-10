// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crl.h"
#include <mbedtls/platform.h>
#include <mbedtls/x509_crl.h>
#include <openenclave/internal/crl.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>

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
    oe_memset(impl->crl, 0, sizeof(mbedtls_x509_crl));
    mbedtls_free(impl->crl);
    oe_memset(impl, 0, sizeof(crl_t));
}

oe_result_t oe_crl_read_der(
    oe_crl_t* crl,
    const uint8_t* der_data,
    size_t der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;
    mbedtls_x509_crl* x509_crl = NULL;

    /* Clear the implementation */
    if (impl)
        oe_memset(impl, 0, sizeof(crl_t));

    /* Check for invalid parameters */
    if (!der_data || !der_size || !crl)
        OE_RAISE(OE_UNEXPECTED);

    /* Allocate memory for the CRL */
    if (!(x509_crl = mbedtls_calloc(1, sizeof(mbedtls_x509_crl))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the CRL structure */
    mbedtls_x509_crl_init(x509_crl);

    /* Parse the DER data to populate the mbedtls_x509_crl struct */
    if (mbedtls_x509_crl_parse_der(x509_crl, der_data, der_size) != 0)
        OE_RAISE(OE_FAILURE);

    /* Initialize the implementation */
    _crl_init(impl, x509_crl);
    x509_crl = NULL;

    result = OE_OK;

done:

    if (x509_crl)
    {
        mbedtls_x509_crl_free(x509_crl);
        oe_memset(x509_crl, 0, sizeof(mbedtls_x509_crl));
        mbedtls_free(x509_crl);
    }

    return result;
}

oe_result_t oe_crl_get_next_update_date(
    const oe_crl_t* crl,
    oe_issue_date_t* issue_date)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;

    /* Check the parameter */
    if (!crl_is_valid(impl) || issue_date == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    issue_date->year = impl->crl->next_update.year;
    issue_date->month = impl->crl->next_update.mon;
    issue_date->day = impl->crl->next_update.day;

    issue_date->hours = impl->crl->next_update.hour;
    issue_date->minutes = impl->crl->next_update.min;
    issue_date->seconds = impl->crl->next_update.sec;

    result = OE_OK;
done:
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
